# VOS PVM

This directory owns the virtual machine, compiler, snapshot codec, and proof
implementation used by VOS. Runtime and compiler changes are reviewed and
released with the rest of the repository.

## Source provenance

The runtime, compiler, codec, and proof foundations were imported from the Virto JAR fork at
commit `41d31e64b0f5d6c57a43769d7b8785556a311684`. That source descended from
the JAM/JAR implementation and is licensed under Apache-2.0; see `LICENSE`.

Only the execution-related crates were imported. Consensus, networking,
storage, RPC, and node code from the upstream repository are not included.

These crates remain Apache-2.0 licensed independently of the AGPL-licensed VOS
host and application framework.

VOS-specific evolution starts from the imported commit. This directory is the
only place in the repository where upstream JAM/JAR terminology and
conformance notes belong.

## Standard conformance

The current standard profile is pinned to the official Gray Paper v0.8.0
release. Its checked-in instruction and block-gas corpus, provenance, and
regeneration command are documented in
[`runtime/tests/VECTORS.md`](runtime/tests/VECTORS.md). The older GP 0.7.2/Jar
fixtures remain explicitly separate and exercise only the temporary private
adapter.
