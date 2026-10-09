# Slice 1: PVM base

Plan v2 for build step 1 of `core-model.md` (draft 5, section 16), work
items 1–5. v1 was reviewed by a second-opinion review; v2 folds in its
findings. Tags as in the core model.

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
2. **Remove every JAR leftover** (core model section 12; checklist in the
   appendix).
3. **Page-proportional memory:** machine memory structures sized to mapped
   pages, never to the 4 GiB space (item 1), in the runtime and in the
   prover's commitments.
4. **Native dirty-page tracking,** including host writes (item 2).
5. **The machine pool and prepared-program cache,** with `instantiate`,
   gated by a differential test against freshly built machines (item 3).

Out of scope:

- the agent framework (slice 2);
- the node host and native extensions (designed in slice 2's planning
  run);
- storage and replication;
- the Ristretto and scalar precompile ids (item 13);
- JIT host-call exit tuning (item 6, after slice 2);
- the privacy track, which starts in parallel (last section).

## Workspace [decided]

`vos-core` becomes the new core's tree. Its workspace keeps:

- `pvm/*`, replaced by the ported saga crates;
- `support/vos-raft` and `support/merkle-crdt`.

The rest of master's workspace is built on the JAR runtime and leaves the
branch in slice 1. Those crates stay on master and in history.

### What leaves, and where it returns

Nothing here is forgotten. Each piece returns, redesigned against the new
core, in the build step named (core model section 16), or is replaced.

| Leaves the branch | What it is | Returns |
|---|---|---|
| `vos/src/node.rs` (20k lines), `runtime.rs`, `extension.rs` | the node host: process, scheduling, the native-extension host | step 2, redesigned. The node host and extensions are designed in slice 2's planning run. |
| `vos/src/ingress`, `ssh_ingress.rs` | HTTP and SSH client ingress | step 2: HTTP ingress with client sessions; SSH later |
| `vos/src/abi`, `log_impl.rs` | guest/host ABI, guest logging | step 2 |
| `vos/src/refine_payload.rs` | work-result wire format | step 2, redesigned |
| `vos/src/network` (8.8k lines) | libp2p networking | step 3, as the replication transport |
| `vos/src/raft` (5.4k lines) | master's Raft integration | replaced in step 3 by the node log writer and the new driver |
| `vos/src/actors` (11k lines) | actor storage handles, `CommittedMap`, codec | step 2 (tables); step 4 (`CommittedMap` on the compressed format) |
| `vos/vos-macros` | `#[actor]` and `#[messages]` | step 2, keeping the same shape |
| `vos/src/zk`, `crypto`, `provable.rs`, `attestation.rs`, `task_abi.rs` | proof plumbing, witness-delivered input | step 5 and the privacy track |
| `vos/src/crdt.rs`, `commit.rs` | CRDT commit | step 6 |
| `vos/src/pvm_image.rs`, `data_layer.rs` | JAR kernel continuations | replaced by step 4's snapshots |
| `vos/src/effect_log.rs` | replay log | does not return (core model non-goal) |
| `vos/src/service` (42k lines), `registry.rs`, `jobs.rs`, `effects.rs` | the v2 service layer | replaced by agents; does not return |
| `vos/tests`, `vos/examples` | v2 tests and examples | rewritten with the parts they test |
| `vosx` (27k lines) | CLI and daemon | step 2: a minimal CLI to run one node; the rest later |
| `extensions/prover` | host-side prover | step 5 and the privacy track |
| `extensions/substrate` | Substrate (Kreivo) light client | with the extension host, after step 2 |
| `tests/fixtures/extensions/*` | extension test fixtures | with the extension host |
| `clerk-witness`, `actors/clerk-*`, `tests/fixtures/provable/clerk-apply`, `tests/acceptance/clerk` | Clerk ledger, bridge, settlement, fixtures and acceptance tests | step 5, on the compressed format |
| `tests/fixtures/actors/crdt-counter` | CRDT fixture | step 6 |
| `pvm/proof/fixtures/fibonacci` | actor fixture built on master's `vos` framework | step 2, with the actor framework |
| `pvm/proof/fixtures/{clerk-refine-bench,voucher-check}`, `pvm/proof/tests/to-port/voucher_check_smoke.rs` | Clerk prover workloads built on master's `vos` framework; the voucher-check smoke test | step 5, re-pinned there |
| `tests/fixtures/wasm` | WASM fixtures | only if a WASM path returns |
| `actors/space-authority`, `actors/space-registry` | space governance and registry | step 2 or 3, as the catalog |
| `services/vos-service`, `examples/` | v2 examples | rewritten for the new framework when it lands |

**Carried to step 5:**

- Move the Ristretto and scalar ids 110–114 into the VOS range, price
  them and serve them on the refine host. Then delete the exception in
  `pvm/proof/src/core/ecall.rs`'s tracer allow-set test, so the tracer and
  the refine host serve exactly the same calls.
- Prove refines that call `instantiate`. Proof tracing runs without a
  pool, so the call reaches the embedder there, as on JAM. Proving it
  means the bundle commits to the pool's programs by code hash, and the
  collector learns each instantiated machine's program from that hash.
| `docs/` (the book), `book.toml` | documentation | rewritten as the core lands |
| `scripts/`, `justfile`, `deny.toml` | tooling | rebuilt for the new tree in step 1.1 |

## Starting point

| Crate | Saga (lines) | Master (lines) | Notes |
|---|---|---|---|
| `pvm/runtime` | 35,342 | 27,269 | 0.8.0 interpreter and JIT, refine host, inner machines |
| `pvm/compiler` | 7,015 | 6,210 | RISC-V to PVM; `link_elf_spi` for standard programs |
| `pvm/program` | 449 | — | standard program parsing and layout |
| `pvm/codec`, `codec-derive` | 1,572 | 1,572 | unchanged |
| `pvm/proof` (with verifier, precompiles, derive) | 69,334 | 61,782 | refine prover and collector, chips |

**JAR is the default, not an option.** `Interpreter::with_memory` passes
`IsaMode::Jar`, and the legacy `TracingPvm::new` inherits the interpreter's
mode. Many proof tests therefore run under JAR without asking for it:

- all of `prove_vos_actor`;
- the settlement verifier's tests (`settle_run`, `settle_transpile`), which
  also use the JAR linker and blob loader;
- `voucher_check_smoke`;
- the benches.

`settle_run` silently skips when its program is missing.

## Steps

Each step is a series of commits that leaves the workspace building and its
tests passing. After every step from 1.2 on, the conformance vectors run on
both backends together with the prover library suite.

### 1.1 Port, tooling and baseline

- **Port and trim.** Replace `pvm/*` with the saga's crates at `766f4860`,
  apply the precompile change from `6659ddea`, and trim the workspace.
- **Guest toolchain in-tree.** Bring the `riscv64em-vos` target spec and
  linker script into `pvm/`, with SJ's explicit read-write base. Investigate
  the linker's "unresolved return_fixup" warning.
- **One test runner, and CI.** The runner covers:
  - the runtime, compiler and prover library suites;
  - the conformance vectors on both backends;
  - guest builds.

  CI runs it on every push, plus a grep check behind the "no JAR" gate.
- **Spike harnesses in-tree.** Move S1's snapshot harness, S2's nesting
  harness and S5b's precompile checks into the runner as benches and tests,
  so later steps measure this branch rather than the spike worktrees.
- **Baseline.** Record:
  - test counts;
  - which suites run under JAR;
  - S2's machine-creation and refine fixed-cost numbers;
  - the cost of creating a JIT machine (`memfd_create`, `ftruncate` and
    three mappings of more than 4 GiB) against the 50 µs gate.

### 1.2 Remove JAR

Removing JAR takes four stages, in this order:

1. **Flip the defaults.** Every constructor defaults to the Gray Paper
   profile. The whole suite then shows what really depends on JAR.
2. **Port what must survive, before deleting anything.**
   - The settlement verifier's tests move to `link_elf_spi` and the
     Gray Paper tracer. `settle_run` fails, not skips, when its program is
     missing, and the runner builds that program.
   - The passing `prove_vos_actor` cases and `voucher_check_smoke` move the
     same way.
   - Gray Paper versions of the negative gates (below) exist before their
     JAR versions are deleted.
   - The settlement verifier's cycle count is re-measured under 0.8.0 and
     recorded in `spikes.md`. The core model's 10.7M figure was measured
     under JAR.
3. **Delete** everything on the appendix checklist. Things that must stay:
   - `backing.rs`, which is the JIT's memory (window and memfd). Only its
     JAR helpers go (`map_pages`, `read_page`/`write_page`,
     `write_init_data`, the non-Linux shared store). `cap::Access` moves
     before `cap.rs` is deleted, and the rest is renamed, for example to
     `recompiler/window.rs`.
   - `ParsedCodeBlob`, replaced by `vos_pvm_program::CodeBlob`, after
     which `program.rs` is deleted. `parse_code_blob` is JAR's format; the
     standard path already uses `parse_compact_code_blob`.
   - The legacy `TracingPvm`, in the Gray Paper profile. It drives
     `prove_chain`, chained segments (item 7) and every negative suite.
4. **Simplify the constraints, with a soundness gate.** Removing the
   ISA-profile column means substituting the literal 0 and simplifying.
   Three constraints change:

   | Constraint | Where | After the substitution | Guard against |
   |---|---|---|---|
   | Address validity for scalar memory | CPU chip | `is_standard_mem_h = is_memory` | deleting it, or substituting 1, which silently drops the guards against access below 64 KiB or wrapping past 2^32 |
   | Host-call continuation | CPU chip | `continues = acknowledged`; the `acknowledged·isa_profile` term vanishes | stays degree 2; acknowledged still implies soft_host |
   | Program-memory lookup tuple | both sides | the limb is dropped from both | removing it at different positions on each side |

   - **Tightened rule:** a continued host call has exactly one precompile
     selector (`precompile_selector_sum = continues`). The ProgramMemory
     builder asserts that an allowed call has a non-zero dispatch. Dispatch
     0, "continue with no chip row", existed for the JAR stubs and goes
     with them.
   - **Negative tests that gate the change,** in the Gray Paper profile:
     - a load and a store at 0x2000, and at 0xFFFF_FFFC + width, are
       rejected;
     - an unallowed `ecalli` that the prover acknowledges is rejected;
     - an acknowledged call with dispatch 0 is rejected;
     - a BLAKE2b row whose selector is cleared is rejected;
     - the existing negative suites pass.
   - **A second reviewer** signs off on the constraint diff itself, not only
     on green tests.

The proof format is not re-pinned here; step 1.4 does it once.

### 1.3 Precompiles

- **BLAKE2b compression** is `ecalli 0x400`. It is served in place by the
  refine host for outer and inner machines, and recorded by the refine
  collector (ported from S5b).
- **The guest shim** (`pvm/proof/precompiles`) uses the id and falls back to
  software on `WHAT`. It no longer passes JAR's capability slot in `a5`.
  Every precompile takes a pointer in φ[7] and leaves registers unchanged.
  The stale comments that say φ[10] holds the h pointer are fixed, with a
  test.
- **Gas** [decided]:
  - a precompile call costs a fixed amount in VOS gas, set from its native
    cost;
  - results are identical across hosts only for runs that complete.

  The AIR does not constrain gas; only the replayed state commitment binds
  it. So the price must be charged identically by the interpreter, the JIT
  and the tracer, and VOS gas vectors pin it on all three paths. They
  cover gas after an in-place precompile and after a `WHAT` answer: GP
  charges 10 for an unknown id, and the JIT charges 10 inline per `ecalli`
  today. Once gas leaves the published statement (core model section 11.4,
  requirement 4), the price matters only to the runtime.
- **Tests:**
  - outputs agree across VOS, a JAM-like host answering `WHAT`, and
    software;
  - the tampering tests from S5b;
  - a precompile write marks its page dirty (step 1.5).

### 1.4 Page-proportional memory (item 1)

- **Interpreter.**
  - `SparseMem`'s million-entry page table becomes a two-level table: a
    1,024-entry directory with 1,024-entry leaves allocated on first touch.
  - Each leaf holds a page's frame and its permission, so one walk serves
    both lookups. A one-entry cache of the last page used keeps the common
    access path short.
  - Inner machines stop setting a second million-entry permission table.
- **JIT.** Permissions record the ranges changed since the last sync.
  `NativeMemory::sync_permissions` applies only those, never diffing the
  full table. The 4 GiB window stays reserved, which costs nothing until
  pages are touched.
- **Prover.**
  - The refine collector stops hashing the flat permission table at every
    revision. The permission commitment becomes a canonical run-length
    encoding, and value scans become page-proportional too.
  - The architectural state commitment drops the JAR fields (ISA mode, gas
    model, `mem_cycles`, and the sbrk-era `heap_base`, `heap_top` and
    `max_heap_pages`).
- **One re-pin.** All proof-format changes are collected and the proof
  format version and canonical program commitments re-pinned once, at the
  end of this step:
  - the ISA column (1.2);
  - the allow-list (1.2);
  - the state-commitment fields;
  - the permission encoding.

  The voucher-check fixture returns in step 5 and is pinned there.
- **Gates:**
  - creating a small actor's machine costs ≤ 50 µs on both backends;
  - a fresh JIT machine's first resume no longer costs about 0.5 ms;
  - the interpreter, which is also the prover's tracer, slows S1's compute
    workload by at most about 10%.

### 1.5 Dirty-page tracking (item 2)

- **Interpreter:** a dirty bit per frame, set on every write path.
- **Host writes,** on both backends: every host path into guest memory
  marks the page dirty. That covers `poke`, `fetch` and `state_read`
  results, precompile output, `memory_mut` and `write_bytes_checked`.
  The raw `DerefMut` on `NativeMemory` is removed, so no path can bypass
  it.
- **JIT:** three options are measured, and the winner is chosen
  [decided: Linux ≥ 6.7 is an acceptable node requirement]:
  - **(a) Write-protect with the existing fault handler: the baseline.**
    Expected to lose for handlers. A pooled handler touches about 3–10
    pages per use, each costing a fault plus `mprotect`, and re-protecting
    flushes TLBs on every core: about 10–40 µs per call. It also fragments
    mappings toward `vm.max_map_count`.
  - **(b) A store barrier in generated code.** It keeps a dirty list
    (check, then append on first write) rather than a whole-space array.
    The stack is handled as a used range, so spills pay nothing.
  - **(c) userfaultfd write-protect in async mode plus `PAGEMAP_SCAN`,**
    with `UFFD_USER_MODE_ONLY`. No signal and no per-store cost; one ioctl
    collects and re-protects. Needs Linux ≥ 6.7.

  If fault handling is involved, the handler must:
  - read the write bit;
  - tell a PVM read-only fault from a clean-page fault through the PVM
    permission byte;
  - resume without moving the instruction pointer.

  `sync_permissions` must never mistake tracking protections for PVM
  permissions. The alternate signal stack is installed on every executor
  thread, not only the first.
- **Gates:**
  - capturing a 3-page delta takes ≤ 20 µs;
  - tracking slows S1's compute workload by ≤ 5%;
  - S2's actor fits acquire, use and reset within the pool gate below.

### 1.6 Machine pool and prepared programs (item 3)

- **Prepared programs** (decoded, and JIT-compiled) are cached by program
  hash, never per thread.
- **The pool** keeps idle machines per program hash. A process holds about
  30k pooled JIT machines at most, since each reserves more than 4 GiB of
  address space. That is a pool limit.
- **Acquire** returns an idle machine or builds one from the program image.
- **Release** resets the machine to exactly a freshly built one.
  - **Memory, on the interpreter:** a leaf entry points either at a shared
    image page or at an owned frame. Reset drops the owned frames.
  - **Memory, on the JIT:** reset copies each dirty page back from an
    in-memory image, and uses `MADV_REMOVE` for pages that are zero in the
    image. No private copy-on-write mapping is used, because the JIT's host
    and guest views are two shared mappings of one memfd.
  - **Everything outside guest memory** returns to a fresh machine's
    values:
    - registers and gas;
    - `pages` changes, native protections and the window's permission
      bytes;
    - the value and permission revision counters, which the prover's cache
      is keyed by (reset them, or use a global generation);
    - fast re-entry state, any pending host call, and the gas-charging
      flags;
    - cached block starts.
- **`instantiate(code_hash)`** is a VOS refine extension that returns a pooled
  machine. A parity test checks that its layout matches the JAM loader's
  (`machine`, then `pages` and `poke`) bit for bit.
- **The differential test** is a property test over adversarial sequences.
  After each reset, the pooled machine must equal a machine built fresh from
  scratch, compared through raw dumps of pages, permissions, registers and
  the fields above. It is never compared through the same reset code, which
  could hide its own bug. The sequences include:
  - guest writes, `pages` changes, precompile output, and `poke` and
    `state_read` writes;
  - release in the middle of a host call;
  - release after running out of gas mid-block;
  - release after a fault on a store that straddles two pages.
- **Gates:**
  - pooled acquire plus reset ≤ 5 µs for a small actor;
  - a new machine ≤ 50 µs;
  - refine fixed cost ≤ 50 µs (core model section 14).

### 1.7 Acceptance

Rerun the in-tree S1, S2 and S5b benches against the finished base:

- snapshot capture plus restore from pooled machines;
- nested invocation;
- refine fixed cost;
- precompile proving.

Update `spikes.md` and section 14 of the core model with the results.

## Gates

| Gate | Threshold |
|---|---|
| Conformance | all v0.8.0 instruction and gas vectors pass on both backends, after every step |
| Prover | library suite, ported settlement-verifier tests, and S5b's agreement and tampering tests pass |
| Soundness of the constraint change | Gray Paper negative gates pass; a second reviewer signs off on the diff |
| Machine creation | ≤ 50 µs, both backends |
| Interpreter speed | ≤ about 10% slower on S1's compute workload |
| Pooled acquire plus reset | ≤ 5 µs, small actor, including use |
| Refine fixed cost | ≤ 50 µs |
| Dirty capture | ≤ 20 µs for 3 pages; ≤ 5% overhead on compute |
| Pool isolation | differential test against freshly built machines passes |
| JAR | the CI grep check finds no JAR symbol, opcode, encoding, id, fixture or test |

## Risks

- **Constraint changes:** simplifying the CPU chip's constraints after
  removing the ISA profile is the step most likely to introduce an unsound
  rule. Hence the negative gates and the second reviewer.
- **Dirty tracking:** each option touches either fault handling, generated
  code or a recent kernel interface. The measurement decides between them.
- **Hidden JAR dependencies:** the flipped defaults in step 1.2 are meant to
  surface them early.

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

## Appendix: JAR removal checklist

From the review of plan v1. Paths are relative to `pvm/`.

**Runtime** (`runtime/src`):

- `kernel.rs`, `cap.rs`, `vm_pool.rs`, the JAR `snapshot.rs`, `program.rs`
  (after `ParsedCodeBlob` is replaced).
- `lib.rs`:
  - `ExitReason::Trap` and `ExitReason::Ecall`;
  - `#[default] Jar`;
  - `compute_mem_cycles`, `mem_cycles_for_mode` and the `GAS_PER_PAGE`
    tiers;
  - `pub use kernel::CodeCache`;
  - the JAVM module docs;
  - `GasModel::PerInstruction`.
- `interpreter/mod.rs`:
  - the Jar default in `with_memory`;
  - `compute_runtime_basic_block_starts` and `charges_jar_sentinel`;
  - the Jar→`Trap` mapping;
  - `heap_base`, `heap_top` and `max_heap_pages`;
  - the `mem_cycles` field and parameter.
- `gas_cost.rs`: the `isa_mode` parameter and its Jar branches.
- `gas_sim.rs`: `JarState`, and the Jar default in `new()`.
- `instruction.rs`: `Opcode::Ecall`, `from_runtime_byte`,
  `from_byte_in_mode`, `is_runtime_terminator`, `decode_runtime_opcode_fast`.
- `recompiler/codegen.rs`: `EXIT_ECALL`, `EXIT_TRAP`, the Jar decode
  branches, and `(Jar, 101) => 254`.
- `recompiler/standard.rs`: `6 => ExitReason::Ecall`.
- `recompiler/mod.rs`: Jar references.
- `inner.rs`: the `Trap`/`Ecall` handling.
- `backend.rs`: the `isa_mode` field.
- `backing.rs`: the JAR helpers only (see step 1.2).
- Docs mentioning GP v0.7.2 in `spi.rs`, `refine.rs` and `args.rs`;
  `SPECIFICATION.md`; `VECTORS.md`; the `runtime/tests/vectors` corpus.

**Compiler** (`compiler/src`):

- `OpcodeEncoding::CapabilityManifest` and its opcode renumbering.
- `link_elf` and `link_elf_with_argument_pages`.
- The `0x800` marker and `emit_ecall` / `ecall_marker` logic, with their
  tests.
- The tests in `emitter.rs` that use `cap::Access` and
  `program::build_blob`.
- The tests in `assembler.rs` that run on `kernel::InvocationKernel`.

**Prover** (`proof`):

- `actor.rs`.
- The ISA-profile column in the CPU and ProgramMemory chips and the lookup
  relations.
- `side_note.rs`: `isa_profile_tag` and the `isa_mode` field.
- `segment.rs`: the `isa_mode` threading.
- `chips/cpu/trace_fill.rs`.
- `core/tracing.rs`: `new_capability_manifest`, and `new` inheriting the
  mode.
- `refine.rs`: the JAR state-commitment fields and the `Trap` exit kind.
- `core/ecall.rs`: the lifecycle stubs (ids 1, 2, 4, 5, 6, 26), the
  `ECALL_VOS_*` capability calls (117–119), and `run_with_vos_stubs`.
- `lib.rs` (the `Ecall` handling).
- The JAR blob tests, and the 9 `JAR\x02` blobs in
  `fixtures/hash-bench`.
- `benches/actors.rs` and the JAR examples.
- JAR cases in `host_call_pc.rs`, `cpu_memory_zone_gate.rs`,
  `host_call_dispatch_gate.rs` and `program_identity.rs`, each replaced in
  Gray Paper form first.

**Guest shim** (`proof/precompiles/src`):

- `VOS_OBJECT_CAP` in `a5`, and the documentation about an immediate of at
  most 127 and the program-cap range.
- The `a5` capability in `ristretto.rs` and `scalar.rs`, and the same
  check in `blake2b.rs`.
