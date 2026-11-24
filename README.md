# VOS

VOS runs spaces: groups of nodes that host agents, programs compiled to
the PVM (the JAM Gray Paper's RISC-V virtual machine), each agent
replicated over its own log. What an agent attests at a window's cut is
proved with a STARK and anchored at a venue (the JAM statements service,
or Kreivo's spaces pallet).

This tree holds the first part of VOS to land: [`pvm/`](pvm/README.md),
the virtual machine and its prover, and standalone libraries under
`support/`. The node, the agents and the device side follow from the
`vos-core` branch, in a later change.

## What is here

- [`pvm/`](pvm/README.md): the runtime (interpreter and recompiler), the
  compiler (RISC-V ELF to PVM), the program format and codec, the actor
  ABI and the committed maps' tree.
- [`pvm/proof/`](pvm/proof/README.md): the prover and its verifier, the
  recursion AIR and the masked final wrap (format 39), the device format,
  the statement and anchor crates a venue links, the verifier kit, the
  fuzz targets and the golden fixtures. Its README defines the terms the
  docs use (kernel, shape, install record, attest, segment, leaf, fold,
  wrap). Read its [SECURITY.md](pvm/proof/SECURITY.md) and
  [AUDIT.md](pvm/proof/AUDIT.md) first.
- [`support/merkle-crdt/`](support/merkle-crdt/README.md): a `no_std`
  replica for operation-based Merkle-CRDTs, after Sanjuán et al.: a DAG of
  signed, authored nodes per sync scope, applied incrementally in causal
  order, over a store the caller implements. The node side builds on it.
- [`support/vmls/`](support/vmls/README.md): `vmls`, an MLS layer over
  mls-rs, with storage in the caller's store (committed with the caller's
  own rows), candidates processed on a copy and swapped in on
  confirmation, and a proposal policy.
- The design: [`docs/design/proving.md`](docs/design/proving.md) (the
  proof layers, formats, masking, verifiers, roots and anchors, and the
  mobile device profile), [`docs/design/recursion-air.md`](docs/design/recursion-air.md)
  (the recursion AIR) and [`docs/design/open.md`](docs/design/open.md)
  (known gaps in proving and at the venues). The first two describe the
  whole system, the node side included.
- [`support/vos-raft/`](support/vos-raft/README.md): Raft consensus as a
  protocol core without I/O (`no_std`), and a deterministic simulator that
  checks it under faults; the node side replicates each agent's log on it.
- `tools/gates/`: the gates' tripwires (`just check-tiers`, `just
  doc-check`); `tools/kreivo/conformance/`: Kreivo's conformance vectors,
  data the verifier kit carries.

## What arrives with the node side

The docs here name what this tree does not hold yet:

- **The node side's code:** `node/`, `agent/` and the rest of `tools/`
  (the docs say "on the node side" where they mean it).
- **Four design docs:** `core-model.md` (where a kernel, an attest and a
  window are defined in full), `identity-and-authority.md`,
  `light-node.md` and `spaces-pallet.md` (Kreivo's spaces pallet, which
  the verifier kit serves; the venue rules it specifies are stated in
  `pvm/proof/anchor/src/venue.rs`), on the `vos-core` branch under
  `docs/design/`.
- **Seven recipes the docs name:** `test-carriers`, `e2e-chain`,
  `conformance`, `test-reads`, `repro-aarch64`, `build-test-actors` and
  `check-no-tools`.
- **Two sections of `pvm/proof/SECURITY.md` that rest on node code:**
  "What leaves the prover role" (the carrier audit) and the device path's
  "A panic is a refusal, not a crash" (true because the node's ingress
  catches it; `vos-pvm-device` has no caller here).

Three stores ship here whose writer is the node side's:

| store | written by | checked here by | until the node side lands |
|---|---|---|---|
| `tools/kreivo/conformance/*.json` | the reference mock, `just conformance` | the verifier kit (`vos_kit.py`): their proof is the fixture's by length and hash, every patch and byte range within its fixture | held to the fixtures; their contents unchecked |
| the known programs' ids (`WINDOW_PROGRAM`, `BALANCE_PROGRAM`, `PREDICATE_PROGRAM` in `pvm/proof/src/constants.rs`) | `just repin`, from the test actors (`vos-kernel-tests`) | nothing: no code here reads them | unchecked and unused |
| `pvm/compiler/tests/fixtures/roomy.elf` | `just build-test-actors` | `derive_pinned` (its hash) | checked, not reproducible here |

So a change here that moves the fixtures fails `just repin` at the kit
(`kit-lock` vendors it) until the vectors are written anew on the node
side.

## Building and the gates

`just` lists the recipes; they run under `nu`. The gates nest, `check ⊆
gate ⊆ ci ⊆ ci-full ⊆ slice-gate`, each named for when it runs. There is
no hosted CI: `ci` is the pre-push hook's recipe (`just install-hooks`),
and a run on another tree (vos-core) is evidence for `pvm/`'s sources,
not for this tree's root files.

| tier | adds | holds | when |
|---|---|---|---|
| `just check` | formatting, the gates' tripwire, the workspace's lints, the fast suites | the final verifier's layout constants (format 39's) | after every edit; minutes, warm |
| `just gate` | the heavy suites, the docs' tripwire, deny, the builds without std, every guest blob against `blobs.lock` and its role, the leak checks, the verifier kit, the fuzz corpora replayed and their reach | `blobs.lock`, the wrap's preprocessed root, the compiler's leaf tables, the kit's lock | before each commit |
| `just ci` | every feature set's lints, the JAR check, the PVM vectors, the bench's cross-host checks, the prover's library tests | the formats' bit counts (`COUNTS`) | before a push |
| `just ci-full` | the prover suites (`just test-proof`: the forgery and soundness gates, the leakage tests at a medium N), the bench's proving tests, the fuzz targets a minute each | `H_FOLD`, the golden fixtures | by hand, before a release candidate, under a 12 GiB memory cap |
| `just slice-gate` | the leakage tests at their full N, the fuzz targets five minutes each | | by hand, before a release |

The forgery and soundness gates run in `just test-proof` alone, which
`ci-full` reaches: not in `check`, `gate` or `ci`.

**What a machine needs:**

| needed by | tool |
|---|---|
| every recipe | `just`; `nu` (the recipes' shell); `git` |
| `check` | `python3` 3.11 or later (`tomllib`); the workspace's nightly with `rust-src` and `wasm32-unknown-unknown` (`rust-toolchain.toml`, which rustup installs) |
| `gate` | `cargo-deny` and its advisory database (fetched); `cargo-fuzz`; `flock`; `rustup` and a network for the stable 1.94.1 toolchain and its `wasm32v1-none` target, which `check-kit` installs when absent; an unset `CARGO_TARGET_DIR` |
| `ci` | `rg`; the guests' nightly with `rust-src` (`pvm/guest/rust-toolchain.toml`, 2026-03-20) |
| `ci-full` | a 12 GiB memory cap (e.g. `systemd-run --user --scope -p MemoryMax=12G -p MemorySwapMax=0 just ci-full`); an x86-64 host with AVX2 for the docs' times (`.cargo/config.toml` builds with `target-cpu=native`) |

`gate` writes outside the checkout: `/tmp/vos-checkout` (a symbolic link
to the checkout, from which the Wasm blob is built so its bytes are the
same from any checkout) and `/tmp/vos-checkout.lock`. Another user's entry
there blocks the build, and the recipe names that user. The toolchain is
pinned in `rust-toolchain.toml`.

Licence: AGPL-3.0-or-later (`LICENSE`), but the five crates the verifier
kit vendors into a chain's runtime and the kit's own files, under the
GPL-3.0-or-later; the code `pvm/` imported keeps its upstream notices
(`pvm/README.md`).
