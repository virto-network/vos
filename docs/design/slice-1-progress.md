# Slice 1 progress

Results for each step of `slice-1-pvm-base.md`. Measurements were taken on
the reference laptop (Core Ultra 7 155H). Other work ran at the same time
(load average about 8–9), so timings carry some noise.

## Step 1.1: port, tooling and baseline

**Done:**

- `pvm/` is the saga's Gray Paper 0.8.0 layer (`766f4860`) plus the BLAKE2b
  precompile (`6659ddea`). The workspace is trimmed to `pvm/*` and
  `support/*`, and the saga's dependency on its agent SDK is replaced by a
  local 64 MiB bundle bound.
- **Guest toolchain** in `pvm/guest/`: the target spec, a linker script with
  the explicit read-write base, the cargo configuration and the pinned guest
  nightly.
- **`pvm/bench`:**
  - the S1 (`snapshots`) and S2 (`nesting`) harnesses and the S5b
    (`precompile`) harness, with their guests in `pvm/bench/guests/`;
  - `tests/precompile_agreement.rs`, which checks that the VOS precompile,
    the JAM fallback and all-software BLAKE2b agree. It fails, not skips,
    when its guests are missing.
- **`justfile`:** `test`, `vectors`, `test-proof`, `build-bench-guests`,
  `test-bench`, `bench`, `fmt-check`, `clippy`, `jar-check` and `ci`. The
  repository has no hosted CI. `ci` runs before every push through
  `.githooks/pre-push` (`just install-hooks`), and `.githooks/pre-commit`
  runs fmt and clippy.
- **Compiler fix:** a call whose return address has no translated
  instruction (a call to a function that never returns, at the end of a
  section) now gets a trap as its return target. Before, its jump-table
  entry stayed 0, which names the refine entry point, so a return would have
  restarted the program. The old warning claimed such a jump would panic,
  which was wrong.

**Baseline:**

| Suite | Result |
|---|---|
| Runtime (`vos-pvm`) | 276 library tests and 25 integration tests pass. Two library tests are `#[ignore]`d (a perf smoke and a measurement that needs environment variables). |
| Conformance vectors | pass on the interpreter and the JIT |
| Compiler | 75 tests pass; one `#[ignore]`d diagnostic |
| Program format, codec | 9 and 68 tests pass |
| vos-raft, merkle-crdt | pass |
| Prover library | 120 tests pass |
| Prover integration, default features | 30 of 31 suites pass. `prove_vos_actor` fails 5 of 35 (JAR blob fixtures, as on the unmodified saga). |
| Prover gates behind `debug-internals` | 8 suites, all pass (see below) |
| Verifier, precompile shim | pass |
| Bench agreement test | passes |
| fmt, clippy (`-D warnings`) | clean |
| `jar-check` | 230 remnants; joins `ci` after step 1.2 |

**Findings while setting up the baseline:**

- **The soundness gates were not running.** Eight gate suites, including
  the memory-zone, host-call dispatch, CPU halt and boundary gates, compile
  only with `--features debug-internals`, so a default test run executes
  none of them. `just test-proof` now enables the feature.
- **The precompile prototype had broken one of them unnoticed.**
  `host_call_dispatch_gate` encoded the host-call id as one byte and
  matched rows by the wire id. Both were fixed for the new `0x400` id and
  the separate dispatch code. Its soundness checks pass: a cleared or
  swapped precompile selector is rejected.
- **The settlement verifier's tests run nothing.** `settle_run` and
  `settle_transpile` "pass" in 0.00 s because the verifier program is not
  built. Step 1.2 ports them and makes them fail when the program is
  missing.
- **One test is parked:** `voucher_check_smoke.rs` sits in
  `pvm/proof/tests/to-port/`, uncompiled, because it depended on master's
  `vos` crate. Step 1.2 ports it back.
- **`#[ignore]`d tests:** two in the runtime, one in the compiler and one in
  the prover (`chip_isolated`). All are diagnostics or perf smokes. Step 1.2
  deleted them; none remain.

**Benches on this tree** (match the spikes; medians):

| | Interpreter | JIT |
|---|---|---|
| Node host call from the agent | 0.12 µs | 0.10 µs |
| Agent machine per refine | 148 µs | 59 µs |
| Actor create + layout | 145 µs | 54 µs |
| Actor first call | 1.0 µs | 368 µs |
| Nested transfer, warm (fixed / per request) | 1,399 µs / 4.8 µs | 892 µs / 2.8 µs |
| Fresh machine per request | 156 µs | 463 µs |
| Snapshot restore, fresh machine | 1.6–2.3 ms | 0.08–0.10 ms (0.5–0.7 ms for the 2 MiB compute image) |
| Snapshot scan, all writable pages | 0.5–1.1 ms | — |

These are the numbers steps 1.4–1.6 must move: machine creation ≤ 50 µs,
pooled acquire plus reset ≤ 5 µs, and refine fixed cost ≤ 50 µs.

## Step 1.2: remove JAR (done)

**Stage 1, flip the defaults.** The `IsaMode` default, `Interpreter::with_memory`,
`GasSimulator::new` and the JIT's constructor now select the Gray Paper
profile. Everything that broke:

- 30 runtime unit tests, of two kinds:
  - JAR-only behaviour: the JAR gas simulator, the GP 0.7.2 per-instruction
    gas model, the private `ecall`. These are deleted in stage 3.
  - Generic instruction tests that hard-code JAR opcode numbers (reverse
    bytes is 111 in JAR, 110 in the Gray Paper) or JAR exits (trap as
    `Trap`). These are ported.
- One prover library test, in `actor.rs` (JAR blob tracing), deleted in
  stage 3.
- `prove_vos_actor`: the same 5 failures as before, on the checked-in JAR
  `.pvm` blobs of `hash-bench`. Several of its other "passing" tests skip
  silently because their fixtures (built on master's `vos` framework) are
  never built.

Every other prover suite passes, including all eight soundness gates and
the conformance vectors.

**Stage 2, port what must survive:**

- **The settlement verifier now builds, runs and accepts** as a standard
  program. Its program had not compiled since a package rename (it called
  the old crate name), which the skipping tests hid. Its tests now fail
  rather than skip when `just build-settle` has not run.
- **`pvm/guest/pvm.ld` fixes,** from linking it:
  - `.text` follows the data instead of sitting at a fixed `0x900000`,
    which a 192 MiB heap arena overlapped;
  - the GOT and relocated read-only data go with the read-write data, where
    `lld` had placed the orphan `.got` below the read-write base.
- **Gray Paper versions of the JAR-only proof gates,** written before their
  JAR versions were deleted:
  - an unhandled host call cannot claim the advanced PC
    (`unhandled_host_call_rejects_forged_resume_pc`);
  - an honest low-zone store is not provable: the CPU AIR rejects the row
    and `prove` refuses the trace (`standard_low_zone_access_is_not_provable`);
  - the acknowledged-host-call gates use a real precompile, since the
    lifecycle stubs they used are gone.
- **A compiled guest proves end to end.** The only `hash-bench` workload with
  source moved to `pvm/bench/guests/diverse`. `tests/diverse_proof.rs` checks
  its output against the same computation done natively, then proves and
  verifies the run on the refine path (about 12 s). The old `prove_diverse`
  passed even when proving failed.

**Stage 3, delete.** Everything in the plan's appendix is gone, and
`just jar-check` finds no remnant:

- runtime: the capability kernel, `cap.rs`, `vm_pool.rs`, the JAR snapshot
  and program formats, `IsaMode`, `GasModel` (with the GP 0.7.2
  per-instruction model), the `Trap` and `Ecall` exits, opcode 3 and the
  shifted unary numbering, the memory-latency tiers, the heap fields, the
  JIT's capability bitmap, and the JIT's register-definition peephole (it
  never fired under the Gray Paper profile, which clears it after every
  instruction);
- compiler: the JAR blob emitter, `link_elf`, the capability-manifest
  opcode encoding and the `0x800` dynamic-ecall marker (CSR `0x800` is now an
  unknown CSR and traps, like any other);
- prover: `actor.rs`, the lifecycle stubs and `ECALL_VOS_*` ids, the
  capability-manifest tracer, `benches/actors.rs`, the JAR blobs; the ISA
  profile no longer threads through side notes and segments, and its
  column is filled with the Gray Paper tag 0 until stage 4 removes it;
- guest shim: the capability slot and padding loaded on every precompile
  call;
- tests and fixtures built on master's `vos` framework (`fibonacci`,
  `clerk-refine-bench`, `voucher-check`, `voucher_check_smoke`), listed in
  the plan's return table for steps 2 and 5;
- the GP 0.7.2 vector corpus (124 files).

**Findings while deleting:**

- **The refine harness charged a JAR initialization fee.** It charged 1,500
  gas per mapped page before running, which Gray Paper 0.8.0's Ψ_M does not.
  For the settlement verifier, with its 192 MiB heap, that was 73,789,500 of
  the 102,671,695 gas first recorded in `spikes.md`. Without it the verify
  takes 10,677,000 instructions and 28,882,195 gas; `spikes.md` and the core
  model are corrected.
- **The v0.8.0 instruction corpus recorded per-instruction gas.** Its
  `expected.gas` was GP 0.7.2's flat model, and three cases depended on it.
  The column and those three cases are gone; every remaining case now runs
  on both backends with exact interpreter-JIT gas agreement, and the 16
  independently derived block-gas vectors pin the gas model. Every other
  expected value in the corpus is unchanged.
- **Invalid opcodes never execute under Ψ.** The interpreter charged invalid
  byte 3 as JAR's `ecall` (100 cycles, ending the block) and other invalid
  bytes at 1 cycle, while the JIT charges them nothing. This cannot matter:
  Gray Paper 0.8.0's `deblob` rejects any program with an invalid opcode at
  an instruction start, so the parity check rightly skips such programs.
- **The prover proves only runs whose memory instructions complete.** A
  run ending in a memory exception (a page fault, or a low-zone access,
  which panics) has no proof; proving refuses it before building the trace.
  This is the existing design, which the deleted JAR gate never exercised.
  It does not limit attestable methods, whose proofs are of completed
  calls, but the privacy track should state it.
- **Proof format.** The refine bundle format is now version 3: the slice-exit
  tags are renumbered without `Trap` and `Ecall`, and the machine-state
  commitment no longer hashes the ISA profile, the gas model, the heap
  fields or the memory tier (domain tags `refine-execution-transcript/v2`,
  `refine-machine-state/v3`). The proof's allowed host calls are now exactly
  the precompiles, so ProgramMemory commitments change only for programs
  that contained a lifecycle stub.
- **For step 1.3:** the Ristretto and scalar precompile ids (110–114) are
  still outside the VOS range `0x400..=0x4ff`, and the plan's remark that
  the JIT charges 10 gas inline per `ecalli` no longer holds: that charge
  was JAR's inline `GAS` capability and is gone.

**Stage 4, remove the ISA-profile column.** After stage 3 the column was
always 0, pinned through the ProgramMemory lookup. It now leaves both chips
and the program-memory tuple (34 → 33 limbs), with 0 substituted into the
three constraints that read it:

- `IsStandardMemH = IsLoad + IsStore`;
- `HostCallContinuesH = HostCallAcknowledged`;
- the acknowledgment-forbids-JAR constraint disappears.

A continued host call must now select exactly one precompile relation
(`precompile_selector_sum = continues`, which replaces the at-most-one
constraint). With the existing `selected_dispatch = continues · dispatch`, a
continued call's committed dispatch is never zero, which covers the plan's
"allowed ⇒ dispatch ≠ 0" without an inverse column. A new gate clears both
the selector and the dispatch on an acknowledged row; it fails under the old
constraint and passes under the new one. A second gate forges a complete,
consistent precompile continuation on a trap row; the AIR rejects it. Proof
format 22 (Poseidon2 variant 23).

Fable signed off on the constraint diff, with no blocking findings: the
substitutions are exact, the new constraint is strictly stronger, and
nothing else read the column. Follow-ups for the step 1.4 re-pin, which
changes the format again anyway:

- `HostCallContinuesH` is now an alias of `HostCallAcknowledged`, and
  `HostCallAllowed` is implied by a non-zero dispatch; both columns can go.
- The memory-exception boundary rests on one condition: a slice's committed
  exit kind stays bound to its final row, so a prover cannot drop a
  faulting step and present the prefix as a complete run. That binding is
  in the slice commitment, unchanged here.

**Step 1.2 is done.**

## Step 1.3: precompiles

- **Price.** A BLAKE2b compression costs 600 gas on top of its `ecalli`'s
  block gas. Serving one natively takes 173 ns, about 520 time-stamp-counter
  cycles, on the reference laptop (`precompile native` in `pvm/bench`); the
  0.8.0 block-gas model counts cycles, and the price rounds that up. The same
  hash in software inside the guest costs 15,874 gas.
- **One charge, every path.** `vos_pvm::precompile::{price, charge}` is the
  single price table. The refine host charges it before serving, for the
  outer machine and inner machines, observed and not, on the interpreter
  and the JIT; the prover's tracer charges the same. An unpayable call is not
  served: the machine stops out of gas on the call's own counter, as for any
  host call. Tests pin the price on the interpreter, the JIT and the observed
  path; for inner machines; and for the tracer against the host.
- **Guest shim.** Every shim (BLAKE2b, both Ristretto calls, the three
  scalar calls) now falls back to software when the host answers `WHAT`.
  The call loads its id with `li` inside the asm block, so the transpiler
  always sees it, and no longer passes JAR's capability slot. The
  `hash-precompile` bench guest is now built on the shim, so the agreement
  test exercises the shim on VOS, on a JAM-like host and in software. That
  host now charges Gray Paper's 10 gas per unknown call.
- **Register convention.** Docs that placed the pointers in φ[10..12] are
  corrected to φ[7..10], and a test checks the tracer and the refine host
  read the same registers and write the same bytes.
- **Tampering.** S5b's checks are now a test: on a one-hash run, a corrupted
  compression input, corrupted output bytes or a dropped call are rejected;
  the honest run proves.
- **Deferred to step 5.** The Ristretto and scalar ids (110–114) stay
  outside the VOS range for now. The refine host does not serve them yet, so
  on VOS they answer `WHAT` and run in software, and inside the prover the
  wire ids double as relation tags. Clerk brings serving, prices and the id
  move together in step 5.
- **Step 1.5** adds the remaining check: a precompile write marks its page
  dirty.


## Step 1.4: page-proportional memory

- **Permissions.** `PagePerms` is a two-level table of 1,024-page slots.
  Each slot is uniform (one permission) or mixed (one byte per page); a
  write that leaves a slot uniform collapses it back. Laying out or
  unmapping a 4 GiB space therefore costs one entry per slot. The access
  checks, revisions and page-granular fault classification are unchanged,
  and a proptest compares every check, and the canonical runs, against a
  flat one-byte-per-page model.
- **Frames.** `SparseMem`'s page → frame table is a second two-level table,
  with leaves allocated on a slot's first frame. Two touched pages in a
  4 GiB span now cost under 64 KiB, down from a 4 MiB table and a 1 MiB
  permission vector.
- **Deviation from the plan.** The plan put a page's frame and permission
  in one leaf behind a last-page cache. Separate tables keep a uniform
  permission slot from allocating a frame leaf. They cost nothing
  measurable, so the cache was not needed. Five alternating S1 runs put the
  interpreter's compute workload at a median of 186 ms, against 195 ms
  for the step 1.3 build, which is within noise.
- **Layout.** Inner machines and refine layout unmap the space with one
  range and then map each region, instead of building a million-entry
  vector.
- **JIT.** The permission map records changed slots in a bitmap.
  `NativeMemory::sync_permissions` visits only those, keeping a per-slot
  mirror of what it installed, so a slot that ends uniform and already
  matches costs neither a table write nor an `mprotect`. The window's
  per-page table is still what compiled code reads. A window's first sync
  applies every slot, and a cloned map starts with every slot changed. So
  a map attached to a pooled or fresh window always installs in full;
  step 1.6 relies on this.
- **Prover.** The refine collector commits permissions as the map's
  maximal runs (`refine-memory-permissions/v2`: page count, run count, then
  each run's length and permission), which is canonical and proportional
  to the map's changes. Value commitments already scan only allocated
  frames. Refine bundle format 4.
- **Re-pin.** The step 1.2 follow-ups land here. `HostCallContinuesH` was
  an alias of the acknowledgment and is gone. `HostCallAllowed` leaves the
  CPU and ProgramMemory chips (the program-memory tuple drops from 33 to 32
  limbs): an acknowledged row must select exactly one precompile relation
  whose weighted id equals the committed dispatch, so the dispatch is
  non-zero, which holds only for the calls the proof runtime handles. The
  runtime's allow-list is now defined as "dispatch is non-zero", so the two
  cannot drift. The JAR fields had already left the state commitment in
  step 1.2. Proof format 24 (Poseidon2 variant 25). No program commitment
  is pinned in-tree until the voucher-check fixture returns in step 5.
- **Gates** (`machines` in `pvm/bench`, medians of 201 fresh machines):

  | | Before | After |
  |---|---|---|
  | Create + lay out the actor machine, interpreter | 143.2 µs | 5.3 µs |
  | Create + lay out the actor machine, JIT | 52.8 µs | 13.1 µs |
  | First resume of a fresh JIT machine | 368.7 µs | 12.0 µs |
  | S1 compute on the interpreter | 195 ms | 186 ms |

  The JIT's straight runs of S1's small workloads drop from about 400 µs
  to about 60 µs, since every run paid the full permission diff before.
  S2's `nesting` agrees. The agent machine per refine drops from 147 µs to
  6.0 µs on the interpreter and from 55 µs to 15.1 µs on the JIT, and the
  JIT actor's first call drops from 358 µs to 17.1 µs.
- **Review.** Fable found no blocking issues: the column removal is sound,
  and the run encoding is canonical and uniquely decodable. On its advice a
  fresh window syncs in full and a cloned map is marked changed, with a
  test. Before, a drained map attached to a new window would have left it
  inaccessible. It also flagged `RecompiledPvm::set_page_perms` as a second
  writer of the window's table. That function belongs to the standalone
  JIT used by the conformance vectors and writes its own mapping, never a
  `NativeMemory` window, so it was left alone.

**Step 1.4 is done.**

## Step 1.5: dirty-page tracking

- **One capture API.** `Memory::take_dirty_pages` returns the pages written
  since the last capture, by the guest or the host, as sorted page ranges,
  and starts a new period. It covers every page whose contents changed; a
  page a write left unchanged may also appear. Loading a machine starts the
  first period after layout.
- **Interpreter.** Sparse memory keeps a dirty flag per allocated frame
  and a list of written pages, so a store pays one load and a predictable
  branch. Flat memory keeps a two-level bitmap of 1,024-page slots. A range
  covering whole slots marks each slot in one step, so clearing a 4 GiB
  range costs one entry per slot.
- **Host writes,** on both backends: `poke`, `fetch` and `state_read`
  results, precompile output and `write_bytes_checked` all reach guest
  memory through `init_copy`, which marks. `clear_pages` marks too, but on
  sparse memory only pages that hold a frame, since the rest already read
  as zero. The raw `DerefMut` on `NativeMemory` is gone: native memory is
  written only through the marking paths.
- **JIT: three options measured** (`dirty` in `pvm/bench`, on a 4 GiB
  memfd window like the JIT's):

  | Option | Per page written | 3-page capture | Notes |
  |---|---|---|---|
  | (a) `mprotect` + SIGSEGV | 1.4–2.0 µs | 0.7 µs | splits mappings |
  | (b) store barrier | — | — | +13% on S1 compute |
  | (c) userfaultfd + `PAGEMAP_SCAN` | 0.35–0.5 µs | 1.7 µs | no per-store cost |

  Option (b) was measured with a probe that added only the barrier's fast
  path to every store (load the page's byte, compare, branch, with RDX
  saved around it, since no register is free). Even that cost 13% on the
  JIT's compute workload (18.4 ms → 20.8 ms), against a 5% budget. Option
  (c) wins. A fresh page's first write costs the same with it as without,
  and tracking survives `mprotect`, hole punching and host-alias writes.
- **What shaped the design.** Three findings from measuring (c):
  - A page that was never write-protected scans as written, so a capture
    must cover exactly the protected pages.
  - Scanning costs about 0.46 µs per MiB of protected range, written or
    not: 3.9 µs for 8 MiB, 29 µs for 64 MiB and 238 µs for 512 MiB.
    Protecting a fresh 4 MiB costs about 3 µs. Protecting every writable
    page up front would make every capture rescan all mapped memory. Gas
    pays for mapping a page once (the inner `pages` call charges per page),
    but a machine is captured again and again: 238 µs per capture for a
    512 MiB heap, however little the guest writes.
  - Scanning only present pages would avoid that, but a written page that
    is reclaimed to swap loses its page-table entry and would be missed.
- **Design.** Tracking starts per 1,024-page slot.
  - A slot with at most 64 writable pages, such as a small actor's stack or
    heap, starts tracking as soon as the pages are mapped.
  - A larger slot's writable pages are mapped read-only. The guest's first
    write into the slot faults, and the fault handler starts tracking it: it
    write-protects the slot's writable runs, makes them writable and retries
    the store. The handler reads the fault's write bit and the page's PVM
    permission byte, so a guest's real fault is never taken for a first
    write. If tracking cannot start, execution stops with a backend error,
    never a guest fault.
  - Pages that become writable in a tracking slot are protected before the
    guest runs again. Pages that stop being writable are scanned first, and
    what the guest wrote to them goes into the next capture.
  - Captures scan only tracking slots' writable runs, so their cost follows
    the slots the guest writes, never how much it maps.
  - If tracking ever fails, or a tracking slot faults on a writable page,
    every later capture reports the whole span. A machine whose backend
    failed must be dropped, never reused.
  - Both aliases opt out of transparent huge pages, which would track
    2 MiB at a time.
  - The alternate signal stack is now installed on every executor thread.
    Uniform permission changes to adjacent slots share one `mprotect`.
  - **Kernel requirement.** On kernels without asynchronous userfaultfd
    write-protect (before Linux 6.7), the default backend falls back to the
    interpreter and logs a warning once. An explicit request for the
    recompiler fails when its memory is created.
- **Tests.**
  - A proptest checks, on flat and sparse memory, that every changed or
    written page is captured.
  - Native-memory tests cover: captures across permission changes; a large
    slot tracking from its first write; a write after a host clear; a
    failure making every later capture report the whole span; fresh
    windows; and host-alias writes.
  - A precompile's output page is captured on the interpreter (flat and
    sparse) and the JIT.
  - `tests/dirty_pages.rs` runs S1's workflows on the interpreter (sparse
    and flat) and the JIT in lockstep. Their captures must be identical at
    every host call and cover every changed page. Disabling the JIT's
    protection makes it fail.
- **Gates:**

  | | Result | Gate |
  |---|---|---|
  | 3-page capture, interpreter | 0.2–0.5 µs | ≤ 20 µs |
  | 3-page capture, JIT (S1, 8 MiB arena) | 8–12 µs | ≤ 20 µs |
  | S1 compute, interpreter | +2.8% (186.9 → 192.2 ms) | ≤ 5% |
  | S1 compute, JIT | within noise (±3%) | ≤ 5% |
  | New JIT machine (create + first resume) | about 35 µs | ≤ 50 µs |

  Copying and hashing the three pages for shipping adds 9–15 µs. The first
  resume of a fresh JIT machine costs about 6 µs more than in step 1.4,
  since its small slots start tracking at once; a pooled machine pays that
  once. The pool gate's acquire, use and reset of S2's actor are measured
  in step 1.6, once the pool exists.
- **Review.** Fable found no blocking issues. Its should-fix items are in:
  - after any failure, captures report the whole span;
  - a fault on a writable page of a tracking slot fails tracking instead of
    surfacing as a guest page fault, which the interpreter would not
    produce;
  - both aliases opt out of transparent huge pages.

  It also asked for the clear-then-write and precompile tests above, the
  errno save in the fault handler, and the backend warning.

## Reviews of steps 1.1 to 1.3

Fable reviewed the three steps it had not seen, after step 1.5, and
signed off on all three.

- **Step 1.3.** The price is charged from one table on every serving path,
  with the same semantics everywhere.
  - The CPU AIR has no gas column. The proof binds gas only through the
    replayed refine boundary: the machine-state commitment hashes the gas
    at every boundary, and the replay charges through the same
    `vos_pvm::precompile::charge`. So a prover can neither claim a served
    call while skipping the charge nor charge without serving.
  - For the privacy track: a witness-free verifier has no gas in its
    statement, so a slice's exit kind must be bound by the closing chip or
    the public output. The AIR alone cannot tell "stopped, unable to pay"
    from "stopped at a host boundary".
  - Fixed: the BLAKE2b shim passed only a counter's low 64 bits to the
    precompile, so a counter of 2^64 or more would have differed from the
    software result. Such counters now compute in software.
  - Pinned: the legacy prover tracer serves the Ristretto and scalar ids
    110–114, which the refine host answers with `WHAT`, so a program using
    them traces differently there than it runs on VOS. Gating the tracer
    on the runtime's set would leave six chip test suites without input
    until step 5. A test now pins the difference instead, and step 5
    closes it by serving those ids on the refine host.
- **Steps 1.2, stages 1–3.** Nothing JAR-specific survives. The behaviour
  changes beyond removal (the init fee, invalid-opcode gas, the gas
  column) are correct for Gray Paper 0.8.0.
  - `jar-check` now also catches JAR's ISA and gas modes, `mem_cycles`, its
    trap exit, `sbrk` calls and CSR `0x800`.
  - The conformance corpus remains self-made. No public 0.8.0 PVM
    instruction corpus exists:
    - `w3f/jamtestvectors` targets 0.7.1 and has no PVM directory;
    - `JAMdotTech/jam-conformance` keeps PVM traces for 0.6.5–0.6.7 only.
- **Step 1.1.** The compiler fix and the 64 MiB bundle bound are correct.
  The review found holes in the gates:
  - `ci`, run before every push, now includes `jar-check`.
  - The two bench tests that prove (`diverse_proof`, `precompile_tamper`)
    no longer run in it. They sit behind the bench crate's `prove` feature
    and run in `just test-bench-proof`.
  - `just ci-full` is the gate before merging: `ci`, the prover suites and
    soundness gates (`test-proof`), and the proving bench tests. It is
    meant to run under a memory limit.

## Step 1.6: machine pool and prepared programs

- **Prepared programs.** `vos_pvm::pool::MachinePool` installs standard
  programs by code hash: BLAKE2b-256 of the program blob, the hash JAM
  names code by. Each is prepared once per backend, on first use. Programs
  that `machine` creates go through a process-wide cache, replacing the
  per-thread one. That cache is keyed by the exact code bytes and backend,
  which costs less than hashing, and is bounded at 2 MiB per program and
  64 MiB in total.
- **`instantiate`.** A VOS refine extension at `0x480`, the first id of
  the extension half (`0x480..=0x4ff`) of the VOS block; precompiles keep
  `0x400..=0x47f`.
  - φ7 points at a 32-byte code hash. φ7 becomes the new machine's index,
    `WHO` for a hash the pool does not hold, or `FULL` at the machine
    limit.
  - The machine is laid out as the standard layout with no arguments: what
    a loader builds with `machine`, then `pages` (read-only data is mapped
    writable, poked, then made read-only) and `poke`.
  - It costs `machine`'s base, plus, for an installed program, exactly what
    that loader pays in host calls.
  - A refine without a pool, which includes proof tracing, passes the call
    to its embedder, as a JAM host answers an unknown id. Proving refines
    that instantiate is carried to step 5: the bundle must commit to the
    pool's programs.
  - The refine host-call allow-list now names the BLAKE2b precompile and
    `instantiate` too.
- **Pool.** An expunged machine, or one still lent when its refine ends,
  returns to the pool, which keeps at most 4,096 idle machines by default.
  A reset returns it to exactly a fresh build's state:
  - every page written since the last reset is restored from the program's
    image or zeroed;
  - only the permission slots that changed are compared with the image and
    restored;
  - registers, gas, the counter, the pending host call and the
    gas-charging flags return to their initial values.

  A capture for a snapshot does not hide pages from a reset: memory keeps
  every capture since the last reset. A machine whose write tracking
  failed, or whose interpreter memory grew 4 MiB beyond a fresh build, is
  dropped instead.
- **Deviations from the plan.**
  - The plan had interpreter frames point at shared image pages, with a
    reset that drops the owned frames. Instead, a build copies the image's
    few non-zero pages, and a reset restores dirty pages, the same way on
    both backends. Interpreter reset meets the gate at 2.4 µs.
  - Memory revision counters keep counting across resets rather than
    being reset. Caches keyed by them therefore never mistake a reused
    machine for its earlier self. The plan allowed either.
- **Tests.**
  - The parity test checks that an `instantiate`d machine equals one a
    loader builds, before and after a run, on both backends, and that its
    price equals the loader's host-call gas.
  - The differential proptest runs adversarial sequences on a pooled
    machine on both backends: guest stores, straddling stores that fault,
    precompile output, `poke` and `pages` changes, stopping at a host
    call, and running out of gas. It releases the machine, takes it back,
    and requires it to equal a fresh loader-built machine, compared through
    raw dumps of registers, continuation state, permissions and pages, and
    then the result of running a probe on both. Skipping the page
    restores, the permission restore or the register reset each makes it
    fail. `state_read` writes join when slice 2 adds `state_read`.
  - A refine-host test covers the host call: with a pool, an unknown hash,
    no pool, and the pool shared across threads.
- **Gates** (`machines` in `pvm/bench`; S2's actor, medians of 201):

  | | Interpreter | JIT | Gate |
  |---|---|---|---|
  | New machine (create + first resume) | 7–10 µs | about 35 µs | ≤ 50 µs |
  | Pooled acquire + reset, after a use | 2.4 µs | 3.5 µs | ≤ 5 µs |
  | The use itself (map a request page, poke, run to the first exit) | 0.5 µs | 4.1 µs | |
  | Refine fixed cost (S2's agent machine per refine) | 6.3 µs | 16.3 µs | ≤ 50 µs |

  On the JIT, a full acquire, use and reset takes about 7.6 µs, mostly the
  guest mapping a request page each time: one `pages` call, its
  protection, and the first writes to tracked pages. A request region the
  actor framework keeps mapped would remove that; slice 2 designs the
  framework.
- **Reset costs found along the way.**
  - Restoring permissions by unmapping everything and remapping the
    layout marked every region slot changed, so the next native sync
    redid protection and write tracking for all of them. The reset now
    compares only changed slots.
  - Clearing a few dirty pages with `MADV_REMOVE` cost a system call each.
    Short runs are now zeroed through the host alias.
  - The second capture after restoring rescanned the window although no
    guest had run; the reset now forgets its own host writes instead.

  Together these took the JIT reset from 7.5 µs to 3.4 µs.
- **Review.** Fable found no blocking issues and no way for a page,
  permission or state change to survive a reset. Its should-fix items are
  in:
  - **Resident memory.** A native machine counts the pages it zeroed in
    place. Past 256, its reset discards every page and reinstalls the
    image, so an idle machine never keeps a past tenant's footprint
    resident.
  - **Backend errors.** A machine whose backend failed on any call is
    dropped on release, never reset and reused.
  - **Observed runs.** An observed run with a pool is refused, so a traced
    run cannot quietly differ from a live one.
  - **Shared cache.** It resolves the default backend once, instead of
    bypassing the cache for it. Fixing that exposed a race: two threads
    preparing the same program could each keep their own copy. Every caller
    now gets the one cached entry.

  Also from the review:
  - `uninstall` drops a program's idle machines, and machines lent from it
    are dropped when they return;
  - a per-program cap (512 by default) keeps one busy program from filling
    the pool;
  - the pool's locks survive a panic elsewhere, so releasing machines
    while unwinding cannot abort;
  - the code hash and initial counter are documented.

**Step 1.6 is done.**
