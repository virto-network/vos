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

The node's prover (`node/prover`, on the node side) proves a kernel's
statements to the wrap with `vos_pvm_recair::tree::prove_final`.

## Pins, and re-pinning

What a verifier accepts is pinned in files the tree checks against what it
builds. Each is written by a recipe, never by hand, except the two named
last:

| Pin | Holds | Written by | Checked by | Tier |
|---|---|---|---|---|
| `blobs.lock` | every guest blob's SHA-256, stripped: the venue guests (`final-verify.elf`, `statement-service.elf`), the final verifier's Wasm blob and, on the node side, the agent programs and the test actors | `just blobs-lock` | `just check-blobs` | `gate` |
| `pvm/proof/src/constants.rs` | the known programs' ids and the circuits' constants (`H_FOLD`, the leaf circuits) | `VOS_PINS=write` on the `kernel` tests' `constants::`: `vos-pvm-proof`'s for the circuits', and on the node side `vos-kernel-tests`' for the programs' ids, from the test actors | the same tests | `ci-full` (`test-proof`), the programs' ids on the node side; a moved fold circuit moves the wrap's root, which `gate` checks |
| `pvm/proof/fixtures` | the golden fixtures: segment proofs and their patches, the wrap's proofs, the statements' cases | `just fixtures` | `the_fixtures_are_the_generators`: every file the generator's bytes, and no file it does not make | `ci-full` (`test-proof`) |
| `pvm/proof/counts.txt` | the proving gates' counts: JAM gas of a statement judged and refined and of the masked wrap's verify (one segment, the maximum over seeds and the fitted worst shape), the Wasm verifier's instructions; each exact, or within 2% where fitted | `VOS_PINS=write` on the test that measures it: `just repin` for the statement's and the one-segment wrap's, a `test-proof` run of the heavy gates' (`vos-pvm-recair`'s `heavy-gates`) for theirs | the same tests | `check` (the statement's), `gate` (the one-segment wrap's), `ci-full` (`test-proof`, the heavy gates') |
| `pvm/proof/kit/Cargo.lock` | the lock VOS's `check-kit` builds the vendored kit on, VOS's pruned to what the kit links (the kit does not ship it: a runtime resolves the kit's dependencies on its own lock) | `just kit-lock` | `just check-kit` | `gate` |
| `pvm/proof/final-verifier/wasm/blob/Cargo.lock` | the Wasm blob's lock, VOS's pruned to what the blob links: the blob `blobs.lock` pins is built `--locked` on it | `just locks` | `just check-locks`: every package the root lock's | `gate` |
| `pvm/proof/fuzz/Cargo.lock` | the prover's fuzz targets' lock, VOS's pruned to what they link, and the fuzzing tools (`libfuzzer-sys`, `arbitrary`) | `just locks` | `just check-locks` | `gate` |
| `pvm/proof/final-verifier/src/constants.rs` | the wrap's preprocessed root (`PREPROCESSED_ROOT_39`), a venue's verifying key | by hand, at a change of the wrap's circuit | `vos-pvm-recair`'s `recursion` test (`masked::`) and `vos-pvm-proof`'s `constants::` test compute it | `gate`; `ci-full` |
| `pvm/proof/fuzz/replay` | each of the prover's fuzz targets' replay corpus, one archive a target (`<target>.tar`, `fuzz/corpus.py`: the same inputs, the same bytes): inputs kept because they reached a path | `just fuzz-refresh` (seeded from the goldens, fuzzed, merged, packed) | `just fuzz-replay` (unpacked into `fuzz/target/replay/`) | `gate` |
| `pvm/proof/fuzz/device-golden.proof` | the golden device proof `device_verify_mutate` mutates (its io-hash, then the proof), kept so its corpus replays against one proof | the fuzz seed (`cargo run --example seed`, in `just fuzz-refresh`), anew only when the device program no longer accepts it | the device targets, which refuse to start on a golden the program does not accept (`just fuzz-replay`) | `gate` |
| `pvm/proof/fuzz/reach.txt` | the verdicts each of the prover's replay corpora reaches, its accepted goldens among them | from `just fuzz-reach`'s output after `just fuzz-refresh` | `just fuzz-reach` | `gate` |

The node side keeps pins of its own beside these, which its `just repin`
writes with them: the facility's release artifacts (`node/light/android/release`),
the stock kernels' device program ids (`node/light/tests/device.pins`),
the node's fuzz corpora (`node/fuzz/replay`, archives as the prover's) and
Kreivo's conformance vectors over the fixtures (`tools/kreivo/conformance`,
written by the reference mock, `just conformance`), which the verifier kit
carries.

**Constants typed by hand and held by a test,** besides the wrap's root:
format 39's layout and shape (`LOG_SIZES`, `TREE_WIDTHS`, `DEEP_VALUES`,
`samples`, `FRI_ROUNDS`, `LOG_DEGREE_BOUND`, in
`final-verifier/src/{constants,masked}.rs`), held by the final verifier's
own tests (`check`) and `vos-pvm-recair`'s `recursion` test against the
built wrap (`gate`); the formats' bit counts (`COUNTS`, `src/format.rs`),
held by the format tests (`vos-pvm-proof --lib`, `ci`); and the compiler's
leaf tables (`pvm/compiler/src/leaf.rs`), held to the built leaves by
`vos-pvm-recair`'s `recursion` test (`leaf_rows`, `gate`).

The verifier's dependencies resolve once, in the root `Cargo.lock`: the
Wasm blob's and the fuzz targets' workspaces, built apart, keep locks
written from it (`just locks`, which `just repin` runs first, so a moved
lock moves the blob's line of `blobs.lock` in the same run) and build
`--locked` on them; `just check-locks` (`tools/gates/locks.py`) holds every
package of theirs to the root's, and `just deny` checks their graphs'
advisories and sources too. The blob's runner
(`final-verifier/wasm/run`) keeps a lock of its own: it links wasmtime, a
tool that measures the blob and is no part of it. On the node side, `just
repro-aarch64`, which checks the program ids and the circuits' constants
on aarch64 under QEMU, is in no tier: it needs a cross toolchain, and is
run by hand.

The prover's replay corpora hold the goldens' proofs: a change that
moves the fixtures or a device program moves what they reach (an old
golden is another honest proof, and the targets' oracle fails on an
accepted proof that is not a current golden), so `just fuzz-refresh` follows `just repin` there, and
`reach.txt` is written from its `just fuzz-reach` anew.

After a change that moves a guest, a circuit or the lock file, `just
repin` writes every generated store anew in dependency order (guests and
`blobs.lock`, the release artifacts, the device program ids, the
constants, the fixtures, the conformance vectors, the kit's lock file;
the side workspaces' lock files first),
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
