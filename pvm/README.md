# VOS PVM

This directory owns the virtual machine, compiler, snapshot codec, and proof
implementation used by VOS, the actor ABI (`abi`) and the committed maps'
Merkle tree its keys are laid out for (`tree`), both VOS's own. No package
here depends on a path outside this directory (`just check-layers`, which
would allow `support/`'s vendored crates, of which none is depended on, and
exempts by name the prover's kernel tests' dev edges to the testkit and
the model venue). Runtime and compiler changes are reviewed and released
with the rest of the repository.

## What it needs from outside it

The Cargo rule above holds, but these read or build against the rest of
the repository, so the directory is reviewed alone and built, pinned and
merged with the trees around it:

- **The prover's kernel tests** (`proof/tests/kernel`, the exempted dev
  edges): they run a kernel against the agent's reference model
  (`agent/testkit`, and `agent/wire` through it), judge its statements at
  the model venue (`node/venue`), and run the built test actors
  (`agent/test-actors`). They hold the checkers of two pins (the
  constants' and the fixtures'), are what `just repin` and `just
  fixtures` write those pins with, and hold `just test-reads`' tests, in
  `gate`.
- **The verifier kit** (`proof/kit/vos_kit.py`) carries Kreivo's
  conformance vectors from `tools/kreivo/conformance/`, so vendoring it
  and `just check-kit` read that directory.
- **The shared files:** the root `Cargo.toml` and `Cargo.lock`,
  `blobs.lock`, `programs.toml` and the `justfile`. The venue guests
  (`final-verify.elf`, `statement-service.elf`) resolve on the root
  lock, so a dependency change outside this directory can move their
  bytes.

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
which the kit ships with them. Files adapted from third-party code keep
their notices: `proof/NOTICE` (the Nexus zkVM, Stwo), `proof/recair/NOTICE`
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
