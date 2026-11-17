# VOS PVM

This directory owns the virtual machine, compiler, snapshot codec, and proof
implementation used by VOS, the actor ABI (`abi`) and the committed maps'
Merkle tree its keys are laid out for (`tree`), both VOS's own. No package
here depends on a path outside this directory, on any edge, dev edges
included (`just check-layers`, which would allow `support/`'s vendored
crates, of which none is depended on). Runtime and compiler changes are
reviewed and released with the rest of the repository.

## What it needs from outside it

The Cargo rule above holds, but these read or build against the rest of
the repository, so the directory is reviewed alone and built, pinned and
merged with the trees around it:

- **The verifier kit** (`proof/kit/vos_kit.py`) carries Kreivo's
  conformance vectors from `tools/kreivo/conformance/` (data the
  reference mock writes, on the node side), so vendoring it and `just
  check-kit` read that directory.
- **A tripwire over the whole repository:** `vos-pvm-recair`'s
  `gates::pins` (`proof/recair/tests/gates/pins.rs`) reads every Rust
  source of the checkout, the node side's among them, for a call that
  commits an unchecked wiring.
- **Committed fixtures from agent programs:**
  `compiler/tests/fixtures/roomy.elf` is the `roomy` test actor's ELF
  (`agent/test-actors`, on the node side), built there and committed here;
  the directory's tests read the committed file alone.
- **The shared files:** the root `Cargo.toml` and `Cargo.lock`,
  `blobs.lock` and the `justfile`. The venue guests (`final-verify.elf`,
  `statement-service.elf`) resolve on the root lock, so a dependency
  change outside this directory can move their bytes.

## What reads it from outside

- **The agent's kernels proved** (`node/kernel-tests`, on the node side):
  each test actor's kernel re-run from its attest against the agent's
  reference model, read at a cut, proved, folded, wrapped and judged at
  the model venue, with the check of the known programs' ids in
  `proof/src/constants.rs` (the node side's `just repin` writes them) and
  the node side's `just test-reads`. They include the prover's test
  helpers (`proof/tests/common`).

## Source provenance

The runtime, compiler, codec, and proof foundations were imported from the Virto JAR fork at
commit `41d31e64b0f5d6c57a43769d7b8785556a311684`. That source descended from
the JAM/JAR implementation, which was licensed under Apache-2.0
(`LICENSE-APACHE-2.0`).

Only the execution-related crates were imported. Consensus, networking,
storage, RPC, and node code from the upstream repository are not included.

These crates are licensed under the AGPL-3.0-or-later, as the rest of the
repository (`LICENSE` at its root), but for the five the verifier kit vendors
into a chain's runtime (`proof/kit/vos_kit.py`): `vos-anchor`,
`vos-statement`, `vos-pvm-final-verifier`, `vos-pvm-recair-air` and
`vos-pvm-poseidon2`, under the GPL-3.0-or-later (`proof/LICENSE-GPL-3.0`),
which the kit ships with them. The kit's own files are under the
GPL-3.0-or-later too: its scripts (`proof/kit/vos_kit.py`, `check.py`,
`vos-sync.sh`, each with its SPDX header) and the data it vendors, the
golden fixtures it ships (`proof/fixtures/statements.cases` and the
wraps) and Kreivo's conformance vectors (`tools/kreivo/conformance/`),
whose bytes carry no header; the kit's `VENDOR` file states it. Files
adapted from third-party code keep their notices: `proof/NOTICE` (the Nexus zkVM, Stwo), `proof/recair/NOTICE`
(StarkWare's proving circuits, Stwo) and `proof/poseidon2/src/packed/`
(Plonky3), under the Apache-2.0 text in `LICENSE-APACHE-2.0` and Plonky3's
MIT licence.

VOS-specific evolution starts from the imported commit. This directory is the
only place in the repository where upstream JAM/JAR terminology and
conformance notes belong.

## Standard conformance

The PVM is pinned to the official Gray Paper v0.8.0
release. Its checked-in instruction and block-gas corpus, provenance, and
regeneration command are documented in
[`runtime/tests/VECTORS.md`](runtime/tests/VECTORS.md). It is the only
profile.
