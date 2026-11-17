# VOS PVM

This directory owns the virtual machine, compiler, snapshot codec, and proof
implementation used by VOS, the actor ABI (`abi`) and the committed maps'
Merkle tree its keys are laid out for (`tree`), both VOS's own. No package
here depends on a path outside this directory but `support/`'s (`just
check-layers`, which exempts by name the prover's kernel tests' dev edges
to the testkit and the model venue). Runtime and compiler changes are
reviewed and released with the rest of the repository.

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
