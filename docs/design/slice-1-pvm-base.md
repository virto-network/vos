# Slice 1: PVM base

Plan for build step 1 of `core-model.md` (draft 5, section 16), work items
1–5. Tags as in the core model.

## Goal

A Gray Paper 0.8.0 PVM, with nothing from JAR, that the rest of the core
builds on. It consists of:

- the runtime (interpreter and JIT);
- the RISC-V compiler;
- the standard-program format;
- the prover and verifier, on the refine path.

The slice delivers five things:

1. **Port** the saga's 0.8.0 PVM layer (saga commit `766f4860`) into
   `vos-core`, with the BLAKE2b precompile from `exp/gp-precompiles`
   (`6659ddea`).
2. **Remove every JAR leftover** (core model section 12).
3. **Page-proportional memory:** machine memory structures sized to mapped
   pages, never to the 4 GiB space (item 1).
4. **Native dirty-page tracking,** including host writes (item 2).
5. **The machine pool and prepared-program cache,** with `instantiate`,
   gated by a pooled-against-fresh differential test (item 3).

Out of scope:

- the agent framework (slice 2);
- storage and replication;
- the Ristretto and scalar precompile ids (item 13);
- JIT host-call exit tuning (item 6, after slice 2);
- the privacy track, which starts in parallel (last section).

## Workspace [decided]

`vos-core` becomes the new core's tree. Its workspace keeps:

- `pvm/*`, replaced by the ported saga crates;
- `support/vos-raft` and `support/merkle-crdt`.

The rest of master's workspace is built on the JAR runtime and leaves the
branch in slice 1: `vos`, `vos-macros`, `vosx`, `extensions/*`,
`clerk-witness`, the test fixtures and `actors/`. Those crates stay on
master and in history. Later slices bring back what section 17 of the core
model reuses (ingress, networking, `vosx`, the light client, Clerk), as new
crates against the new core.

Why not keep master's crates building beside the new PVM? They depend on
the JAR runtime's APIs. Keeping them would mean two PVMs in one workspace
under renamed crates, which is exactly the duplication the redesign
removes. A clean tree also makes the eventual merge to master a deliberate
replacement, after the heavy cleanup the owner requires.

### What leaves, and where it returns

Nothing here is forgotten. Each piece returns, redesigned against the new
core, in the build step named (core model section 16), or is replaced.

| Leaves the branch | What it is | Returns |
|---|---|---|
| `vos/src/node.rs` (20k lines), `runtime.rs`, `extension.rs` | the node host: process, scheduling, the native-extension host | step 2, redesigned. The node host and extensions are designed in slice 2's planning run. |
| `vos/src/ingress`, `ssh_ingress.rs` | HTTP and SSH client ingress | step 2: HTTP ingress with client sessions; SSH later |
| `vos/src/network` (8.8k lines) | libp2p networking | step 3, as the replication transport |
| `vos/src/raft` (5.4k lines) | master's Raft integration | replaced in step 3 by the node log writer and the new driver |
| `vos/src/actors` (11k lines) | actor storage handles, `CommittedMap`, codec | step 2 (tables); step 4 (`CommittedMap` on the compressed format) |
| `vos/vos-macros` | `#[actor]` and `#[messages]` | step 2, keeping the same shape |
| `vos/src/zk`, `crypto`, `provable.rs`, `attestation.rs` | proof plumbing | step 5 and the privacy track |
| `vos/src/crdt.rs`, `commit.rs` | CRDT commit | step 6 |
| `vos/src/service` (42k lines), `registry.rs`, `jobs.rs`, `effects.rs` | the v2 service layer | replaced by agents; does not return |
| `vosx` (27k lines) | CLI and daemon | step 2: a minimal CLI to run one node; the rest later |
| `extensions/prover` | host-side prover | step 5 and the privacy track |
| `extensions/substrate` | Substrate (Kreivo) light client | with the extension host, after step 2 |
| `tests/fixtures/extensions/*` | extension test fixtures | with the extension host |
| `clerk-witness`, `actors/clerk-*` | Clerk ledger, bridge, settlement | step 5, on the compressed format |
| `actors/space-authority`, `actors/space-registry` | space governance and registry | step 2 or 3, as the catalog |
| `services/vos-service`, `examples/` | v2 examples | rewritten for the new framework when it lands |
| `docs/` (the book) | documentation | rewritten as the core lands |

## Starting point

| Crate | Saga (lines) | Master (lines) | Notes |
|---|---|---|---|
| `pvm/runtime` | 35,342 | 27,269 | 0.8.0 interpreter and JIT, refine host, inner machines |
| `pvm/compiler` | 7,015 | 6,210 | RISC-V to PVM; `link_elf_spi` for standard programs |
| `pvm/program` | 449 | — | standard program parsing and layout |
| `pvm/codec`, `codec-derive` | 1,572 | 1,572 | unchanged |
| `pvm/proof` (with verifier, precompiles, derive) | 69,334 | 61,782 | refine prover and collector, chips |

The saga's PVM layer differs from master's by 297 files (+32.7k −4.6k
lines). The S5b prototype adds 11 files (+359 −40).

## Steps

Each step is a series of commits that leaves the workspace building and its
tests passing.

### 1.1 Port and baseline

- Replace `pvm/*` with the saga's crates at `766f4860`, apply the
  precompile change from `6659ddea`, and trim the workspace (previous
  section).
- Add a test runner that runs the runtime, compiler and prover library
  suites, plus the conformance vectors, on the interpreter and the JIT.
- Record the baseline:
  - test counts;
  - the 5 `prove_vos_actor` failures on JAR blobs, which step 1.2 removes;
  - S2's harness numbers for machine creation and refine fixed cost.

### 1.2 Remove JAR

| Area | Removed |
|---|---|
| Runtime | `kernel.rs` (5,447 lines), `cap.rs`, `vm_pool.rs`, the JAR `snapshot.rs`; the capability-manifest half of `program.rs` (code-blob parsing moves next to `spi.rs`); `IsaMode::Jar` (about 70 references); `GasModel::PerInstruction` (GP 0.7.2); the `ecall` opcode. `backing.rs` stays only where steps 1.4–1.6 reuse it. |
| Compiler | `OpcodeEncoding::CapabilityManifest` with its opcode renumbering, `link_elf`, and the `0x800` dynamic-ecall marker. One encoding remains. |
| Prover | `actor.rs` (JAR blob tracing); the ISA-profile column and JAR constraint branches in the CPU and ProgramMemory chips (about 30 references); the lifecycle stubs (ids 1, 2, 4, 5, 6, 26) and VOS capability calls (117–119) in the host-call allow-list; `run_with_vos_stubs`; legacy tracer paths that only serve JAR blobs; JAR blob tests. |
| Vectors | The 124-case GP 0.7.2/JAR corpus. The 173 v0.8.0 instruction cases and 16 v0.8.0 block-gas cases remain the conformance gate. |

Removing the ISA-profile column changes the proof format. The format
version and canonical program commitments are re-pinned, and the CPU
chip's host-call constraints are re-reviewed for soundness once the JAR
branch is gone.

### 1.3 Precompiles

- **BLAKE2b compression** is `ecalli 0x400`. It is served in place by the
  refine host for outer and inner machines, and recorded by the refine
  collector (ported from S5b).
- **The guest shim** (`pvm/proof/precompiles`) uses the id and falls back to
  software on `WHAT`. Every precompile takes a pointer in φ[7] and leaves
  registers unchanged.
- **Gas** [decided; delegated by the owner]:
  - a precompile call costs a fixed amount in VOS gas, set from its native
    cost;
  - results are identical across hosts only for runs that complete;
  - the prover binds the price wherever a proof binds final gas.
- **Tests:**
  - outputs agree across VOS, a JAM-like host answering `WHAT`, and
    software;
  - the tampering tests from S5b;
  - a precompile write marks its page dirty (step 1.5).

### 1.4 Page-proportional memory (item 1)

- **Interpreter.**
  - `SparseMem`'s million-entry page table becomes a two-level table: a
    1,024-entry directory with 1,024-entry leaves allocated on first touch.
  - `PagePerms` becomes a set of ranges, keeping its uniform read-write
    fast path.
  - Inner machines stop setting a second million-entry permission table.
- **JIT.**
  - `PagePerms` records the ranges changed since the last sync.
    `NativeMemory::sync_permissions` applies only those, never diffing the
    full table.
  - The 4 GiB window stays reserved, which costs nothing until pages are
    touched.
- **Gate:**
  - creating a small actor's machine (S2's actor) costs ≤ 50 µs on both
    backends;
  - a fresh JIT machine's first resume no longer costs about 0.5 ms.

### 1.5 Dirty-page tracking (item 2)

- **Interpreter:** a dirty bit per frame, set on every write path, including
  the host's `Memory` writes (`poke`, `fetch` and `state_read` results,
  precompile output).
- **JIT** [open: decided by a measurement inside this step]:
  - (a) write-protect clean pages and mark them dirty in the existing fault
    handler on first write. No per-store cost; one fault per page per
    epoch.
  - (b) a store barrier in generated code that sets a per-page bit. Cost on
    every store.

  Host writes go through `Memory` and mark pages dirty directly, whichever
  option wins.
- **Gate:**
  - capture of a 3-page delta takes ≤ 20 µs;
  - tracking slows S1's compute workflow by ≤ 5%.

### 1.6 Machine pool and prepared programs (item 3)

- **Prepared programs** (decoded, and JIT-compiled) are cached by program
  hash, never per thread.
- **The pool** keeps idle machines per program hash.
  - **Acquire** returns an idle machine or builds one from the program
    image.
  - **Release** resets the machine to exactly a fresh one:
    - dirty pages are restored from the image;
    - `pages` changes are undone;
    - registers and gas are reset.
  - Program images are shared copy-on-write: frames shared by reference in
    the interpreter, and a private mapping of the image in the JIT.
- **`instantiate(code_hash)`** is a VOS refine extension that returns a pooled
  machine. A parity test checks that its layout matches the JAM loader's
  (`machine`, then `pages` and `poke`) bit for bit.
- **The differential test** is a property test over adversarial sequences:
  guest writes, `pages` changes, precompile output, `poke` and
  `state_read` writes, and faults. After each reset, a pooled machine must
  be indistinguishable from a fresh one.
- **Gate:**
  - pooled acquire plus reset ≤ 5 µs for a small actor;
  - a new machine ≤ 50 µs;
  - refine fixed cost ≤ 50 µs (core model section 14).

### 1.7 Acceptance

Rerun S1 and S2 against the new base, with pooled machines:

- snapshot capture plus restore;
- nested invocation;
- refine fixed cost.

Update `spikes.md` and section 14 of the core model with the results.

## Gates

| Gate | Threshold |
|---|---|
| Conformance | all v0.8.0 instruction and gas vectors pass, interpreter and JIT |
| Prover | prover library suite passes; S5b's agreement and tampering tests pass on the ported code |
| Machine creation | ≤ 50 µs, both backends |
| Pooled acquire plus reset | ≤ 5 µs, small actor |
| Refine fixed cost | ≤ 50 µs |
| Dirty capture | ≤ 20 µs for 3 pages; ≤ 5% overhead on compute |
| Pool isolation | differential test passes |
| JAR | no JAR symbol, opcode, encoding, id or test remains |

## Risks

- **JIT dirty tracking:** both options touch the JIT's fault handling or
  code generation. The measurement in step 1.5 decides between them.
- **Proof soundness after removing the ISA profile:** the CPU chip's
  host-call constraints were written with both profiles in mind. They need
  a focused review, and the negative-test suites must stay green.
- **Saga code quality:** the PVM layer was the self-contained part of the
  saga, with conformance vectors behind it. Step 1.1's baseline shows what
  holds before anything changes.

## Privacy track: first step (in parallel)

A design note, not code:

- options for zero-knowledge proving on the pinned Stwo revision, with
  masking in the prover and in each chip;
- a bundle format without replay for pure attestable programs: with no host
  boundaries, the STARKs and the public output suffice;
- the minimal published format and fixed shape classes;
- the costs of window aggregation.

It goes to the owner and a second-opinion review before any prover code
changes.
