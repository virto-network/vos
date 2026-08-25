# VOS PVM

This directory owns the virtual machine, compiler, snapshot codec, and proof
implementation used by VOS. Runtime and compiler changes are reviewed and
released with the rest of the repository.

## Source provenance

The runtime, compiler, and codec were imported from the Virto JAR fork at
commit `41d31e64b0f5d6c57a43769d7b8785556a311684`. That source descended from
the JAM/JAR implementation and is licensed under Apache-2.0; see `LICENSE`.

Only the execution-related crates were imported. Consensus, networking,
storage, RPC, and node code from the upstream repository are not included.

VOS-specific evolution starts from the imported commit. This directory is the
only place in the repository where upstream JAM/JAR terminology and
conformance notes belong.
