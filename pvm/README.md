# VOS PVM

This directory owns the virtual machine, compiler, snapshot codec, and proof
implementation used by VOS, the actor ABI (`abi`) and the committed maps'
Merkle tree its keys are laid out for (`tree`), both VOS's own. No package
here depends on a path outside this directory, on any edge, dev edges
included (`just check-layers`). Runtime and compiler changes are
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
  `blobs.lock` and the `justfile`. The PVM guests `blobs.lock` pins
  (`statement-service.elf`, the JAM statements service's program, the
  one deployed; `final-verify.elf`, the harnesses' JAM-only program)
  resolve on the root lock, so a dependency change outside this directory
  can move their bytes.

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

## The runtime: backends and threat model

`vos-pvm` (`runtime/`) runs a program on one of two backends, the
interpreter (the reference the proof tracer drives) and the recompiler
(x86-64 Linux, native code). **A backend never changes a result:** the
same program gives the same exit, gas, registers and memory on either
backend and on every host. The code bound is one for both, enforced
before a backend is chosen, and whatever the recompiler cannot take
(code whose native form passes its cap, a mapping the host refuses, a
missing CPU feature, a guest window whose protections would pass its
mapping budget) runs on the interpreter instead of failing.

**How the backend is chosen:** the recompiler is the default where the
host permits it. Once a process, a start-up probe does what a native
machine does: it checks that the CPU has LZCNT, BMI1 and POPCNT, compiles
code and makes it executable, opens `userfaultfd` write-protect (Linux
6.7 or later; the default Docker and Podman seccomp profiles deny
`userfaultfd`, so a default container runs the interpreter), reserves a
guest window and runs a trap natively; it logs the backend chosen and
why (`backend::backend_choice`). The operator's `VOS_PVM_BACKEND`
forces one: `interpreter` skips the probe, `recompiler` is an error on a
host that fails it, and any other value is an error.

**Threat model.** The recompiler is software fault isolation inside the
node's process: compiled guest code runs on the node's threads, each
guest memory access one operand form inside a reserved 4 GiB window
behind an emitted bound check, with page protections and a SIGSEGV
handler. The in-process hardening is a second line against a
code-generation bug, not a boundary of its own: a fault counts as the
guest's only at an exact trap-table entry and inside the guest window
(anything else poisons the machine and is a host error), guard regions
lie on both sides of the window, the JIT's context is not on a page a
small guest offset reaches, a dynamic jump's index is masked after its
bound check (against a mispredicted check), and code is never writable
and executable at once. Nothing confines the process itself: an escape
from compiled code reaches the whole node (its keys, other tenants'
guest memory, its network), as with an in-process WebAssembly engine.
The interpreter runs no guest native code. Moving the recompiler's
execution into a confined worker process is open work
([`docs/design/open.md`](../docs/design/open.md)).

## Standard conformance

The PVM is pinned to the official Gray Paper v0.8.0
release. Its checked-in instruction and block-gas corpus, provenance, and
regeneration command are documented in
[`runtime/tests/VECTORS.md`](runtime/tests/VECTORS.md). It is the only
profile.
