# Slice 5, spike 3: a derived attestable kernel proved on the chain path

Date 2026-10-15. Repository `/home/daniel/src/virto/vos`, worktree
`.worktrees/s5-spike3`, branch `spike/s5-kernel-proof` from `vos-core` at
`3713cb42`; two local commits, `fb3bf2ac` and `13f35c2c`, not pushed. The
`vos-core` worktree was not touched.

Paths: `VC` = the `vos-core` tree at `3713cb42` (unchanged on the spike
branch except where noted), `SP` = `spikes/s5-kernel-proof` on the spike
branch, `CC` = cipher-clerk at tag `v0.3.0` (`b841640b`).

Machine caveat: another spike ran on the machine throughout (load average
about 20). Times are wall clock under that load: Blake2s segments of one
shape took between 4.4 s and 10.3 s within one run. Memory and sizes are
unaffected.

## The answers in brief

1. **Yes.** The chain path's tracer serves BLAKE2b `0x400` in-AIR, as the
   refine path does. One gap: its handler read flat memory only, and a
   kernel's standard layout needs a sparse one. The fix is 49 lines in one
   file, made on the spike branch. No fallback is needed.
2. **The kernel:** an actor's `#[attestable] fn window(…)`, derived by
   `derive(elf)` into a 43,687-byte kernel. It checks two vos-tree
   multiproofs (one per anchor) at the compress level, then runs
   `cipher_clerk::settlement::window`. Natively, the PVM and the proof
   agree on its output in every configuration.
3. **The key number:** at 10^6 rows, **21.4 kernel compressions per row
   read** for 8 journals (32 row reads, 685 compressions), up to 26.3 for
   1 journal. Each row read is one row checked against one root. The
   number grows with log2 of the tree:
   - 14.2 at 10^4 rows;
   - 17.7 at 10^5;
   - 21.4 at 10^6.

   **But kernel compressions are not what sizes a segment.** Two other
   costs dominate:
   - **Steps.** At about 593 steps per compression, a 32,768-step segment
     holds about 2.6 row reads.
   - **The page-Merkle boundary.** Each segment's memory-continuity
     boundary costs 250 to 800 compressions of its own, 6,585 in all
     against the kernel's 685 at the production cut.

   Proved and verified standalone on both channels:
   - **Poseidon2-M31 (format 25)**, 8 journals: 16 segments, 425 s of
     proving, 6.6 GiB peak, 41.5 MB of proof, 3.1 s to verify.
   - **The same on a 131,072-step, 64-page cut:** 4 segments, 232 s,
     17.9 GiB, 10.5 MB, 0.46 s.
4. **Program identity today:** the proof binds the kernel's code and jump
   table through the preprocessed root, which also depends on the
   observed profile and the channel. One kernel showed eight different
   commitments in this spike: five on Blake2s, three on Poseidon2. Its data, and the private arguments, are
   bound only through the initial memory root, which the verifier must
   supply. One id needs three things:
   - a pinned shape class per kernel (small);
   - a split of the initial root into a public data part and a private
     argument and salt part (the real design work, 5.1's salt page);
   - a hash over (`TRANSPILER_VERSION`, `ProgramHash`, class, channel,
     preprocessed root, data root), kept in the install's `Derivation`
     (small).
5. **The proof files** are in `/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/proofs/`:
   - Poseidon2-M31, `PROOF_FORMAT_VERSION` 25, MOBILE PCS (blowup 4,
     38 queries, 20 PoW bits);
   - each segment in bincode and in postcard;
   - one Blake2s (format 24) run beside them for comparison;
   - `INDEX.txt` lists them.

## 1. Does the chain path serve BLAKE2b in-AIR?

**Yes.** All references are to `VC` unless marked.

- **The tracer `prove_chain` consumes is `TracingPvm`.** It is driven by
  `run_with_precompiles` / `step_with_precompiles`
  (`pvm/proof/src/core/tracing.rs:375-422`):
  - it charges the call's VOS price first (`:393-398`, through
    `vos_pvm::precompile::charge`);
  - it matches `ECALL_BLAKE2B_COMPRESS` = `0x400` (`:400-402`;
    `core/ecall.rs:17`);
  - `handle_blake2b_ecall` serves it and records both a `Blake2bRecord`
    for the BLAKE2B chip and a `Blake2bMemOp` (h and m read, output
    written, at the call's timestamp) for the memory ledger
    (`tracing.rs:467-535`);
  - it acknowledges the call so the row continues at the successor
    (`:430-465`).
- **ProgramMemory commits the dispatch identifier** that binds the
  acknowledged row to the BLAKE2b selector, so a prover cannot skip an
  unknown call (`core/ecall.rs:108-138`).
- **The chain cutter carries each window's calls:** `filter_pair` over
  the BLAKE2b streams (`segment.rs:511-515`). The streaming driver is
  `TracingSource`. A live test cuts BLAKE2b calls across windows and
  checks that later windows' images carry earlier outputs
  (`segment.rs:2170-2302`).
- **`prove_chain`** (`prove.rs:726-740`) proves each window with
  `prove_canonical` (`:648-669`) over all 32 components, BLAKE2B
  (index 1) and BLAKE2B_BOUNDARY (index 2) among them (`lib.rs:208-245`),
  under the MOBILE PCS config (`:660`).
- **`verify_chain_standalone`** (`pvm/proof/verifier/src/lib.rs:737-823`)
  anchors the first segment's initial memory root and requires
  `final == next.initial`.

**The gap: flat memory only.**
- **Where:** the handler reads and writes through `self.pvm.flat_mem()`
  (`tracing.rs:493-519`), which panics on a sparse memory
  (`pvm/runtime/src/interpreter/mod.rs:345-349`).
- **Why a kernel hits it:** a kernel in the Gray Paper standard layout
  spans the address space. The stack sits below `2^32 − 2·2^16 − 2^24`
  and the arguments at `0xFEFF0000` (`pvm/program/src/lib.rs:99-175`),
  so it needs `Memory::sparse`.
- **The fix,** in commit `fb3bf2ac`:
  - for a sparse memory, serve through `vos_pvm::precompile::execute`,
    the refine host's own permission-checked serving
    (`pvm/runtime/src/precompile.rs:103-161`), and record the same two
    streams;
  - an unreadable argument panics the machine, as on the refine host;
  - on the spike branch it is `tracing.rs:403` (the call site) and
    `:473-475`, `:547-582`, a 49-line diff (`git diff vos-core -- pvm`);
  - flat memory is unchanged.
- **The Ristretto handlers** (`tracing.rs:563-726`) stay flat-only. That
  does not matter here: derivation refuses ids 110–114 in a kernel
  (`pvm/compiler/src/derive.rs:630-641`).

**What else the chain path lacks for kernels:** a loader. Nothing in
`vos-pvm-proof` builds a kernel's machine.
- **The spike's version:** `SP/harness/src/main.rs:446-522` lays the
  standard program out the way `pvm/runtime/src/refine.rs:284-338` does:
  - regions and permissions;
  - read-only arguments in the standard window;
  - φ0 the halt address, φ1 the stack top, φ7/φ8 the arguments' address
    and length.

  This is what the agent's `kernel()` does
  (`agent/default/src/refine/invocation/kernel.rs:36-66`;
  `agent/default/src/machines.rs:32`).
- **What it costs:** about 40 lines. A `trace_kernel(blob, args)` belongs
  in `vos-pvm-proof` when this is wired.

**Conclusion:** small work. **The refine-path fallback is not needed.**

## 2. The kernel

**The actor:** `SP/actor/src/lib.rs`, actor `Settlements`.
- **Methods:**
  - `#[msg] state(...)` attests;
  - `#[attestable] fn window(space: [u8; 32], window_i: u64,
    root_i: [u8; 32], window_j: u64, root_j: [u8; 32], rows: Vec<u8>,
    proof_i: Vec<u8>, proof_j: Vec<u8>) -> Vec<u8>` (`:58-77`) calls
    `window_kernel::settle`.
- **Build:** vos-core's guest recipe (`pvm/guest` target JSON, linker
  script and cargo config, copied into `SP/actor`), on
  nightly-2026-03-20.
- **Derivation:** `vos_pvm_compiler::derive` gives one kernel:
  - method `0xbb70dbaf`, 43,687 bytes;
  - `ProgramHash` (BLAKE2b-256 of the blob)
    `28cff2be8934042bb40889d80cdb0879fba3be6267620c03af2924dc02e439b9`;
  - `TRANSPILER_VERSION` 1.
- **The proved program is that derived kernel.** It is not hand-written,
  and not the actor's whole program.

**The kernel's logic:** `SP/kernel/src/lib.rs`, crate `window-kernel`.
- **Witness.**
  - **The rows:** per pseudo-account, its row value (cipher-clerk's
    `Account` encoding, 146 bytes) and leaf salt at each anchor
    (`read_rows`, `:417-438`). The value is decoded with cipher-clerk's
    codec.
  - **The proofs:** two vos-tree `BatchProof`s in the SCALE encoding the
    node serves (`node/host/src/roots/mod.rs:224-247`).
- **Hashing, all at the compress level through `0x400`:**
  - **The row's tree key:** the hashed transform
    `H128(key) ‖ escape(key)`, one compression per account
    (`hashed_key`, `:207-222`).
  - **Its value's commitment:** `H("vos/tree/value" ‖ salt ‖ value)`,
    176 bytes, two compressions (`value_hash`, `:202`).
  - **Each opened leaf:** one compression (`leaf_hash`, `:177-200`).
  - **Each branch:** one compression (`branch_hash`, `:150-175`). Its
    81-byte block is packed by word shifts; it is never streamed through
    `blake2b_hash`.
- **The proof check** (`verified`, `:291-366`) mirrors
  `vos_tree::BatchProof::verify` for present claims:
  - levels strictly increase down each path;
  - each opened leaf lies on the side its key's bits select;
  - opened leaves are in strictly increasing key order;
  - no branch has two closed children;
  - the opened leaves are exactly the claims;
  - the rebuilt root equals the anchor's root.
- **The statement:** `cipher_clerk::settlement::window` over the verified
  rows (`statement`, `:440-491`). The output is a status byte plus the
  `NetFlow` encoding, 166 bytes, which the SDK's entry frames as a
  `Vec<u8>` (`u32` count first; `agent/sdk-macros/src/messages.rs:407-420`).
- **Limit:** only rows present at both anchors. An account created inside
  the window needs an absence claim, which this kernel refuses (`ABSENT`).
  Absence costs about the same as presence (a path to the neighbouring
  leaf).
- **The anchors' roots are the committed map's roots,** not a space-level
  root.

**Checks, every configuration** (`generate`, `SP/harness/src/main.rs:168-421`):
- **Native:**
  - the kernel's proof check accepts what `vos_tree::BatchProof::verify`
    accepts, and refuses a claim with one flipped bit;
  - its key, value, leaf and branch hashes equal vos-tree's;
  - its output equals `window` called directly.
- **On the tracer:** the derived kernel's output equals the native one
  (`traced`, `:532-554`).
- **Program identity:** for segment 0 of every proved run,
  `program_commitment_for_profile` reproduces the proof's commitment
  from the program and the profile alone (`prove`, `:618-626`).

**cipher-clerk v0.3.0** is taken from codeberg, tag `v0.3.0`, with
`default-features = false, features = ["settlement"]`. Its
`pvm-precompile` feature is broken against vos-core:
- **Why:** the feature names master's shim crate at VOS rev `9f5337fb`
  (`CC/Cargo.toml:67, 91`), whose BLAKE2b call is the retired id 100
  (`zkpvm/precompiles/src/ecalls.rs:36` at that rev). Derivation refuses
  that id (`derive.rs:630-641`).
- **Without the feature:** `PseudoAccount::of` hashes with the `blake2`
  crate in software (`CC/src/crypto/hash.rs:11-27`;
  `CC/src/conventions.rs:309-320, 344-356`).
  - The 8-journal kernel then takes 834,545 steps instead of 406,342,
    about 13,000 steps per id hash.
  - It cuts into 29 segments instead of 16.
- **The spike's fix:** it patches a stand-in crate named
  `zkpvm-precompiles` (`SP/shim`) that re-exports `vos-pvm-precompiles`
  (`0x400`).
- **Owed by cipher-clerk:** point the feature at vos-core's shim.

**The window inputs** (`generate`):
- **Trees:** 10^4, 10^5 and 10^6 rows, built with `vos_tree::update`:
  - random 16-byte ids under the hashed transform, 146-byte values;
  - plus the 16 pseudo-accounts (outgoing and incoming) of 8 journals,
    opened with `PseudoAccount::open`.
- **Two versions:**
  - version i;
  - version j, in which the 16 accounts grew and 1,000 other rows
    changed, salted from a new seed.
- **Windows:** 1, 2, 4 and 8 journals, that is 2, 4, 8 and 16
  pseudo-accounts, and twice that many row reads (both anchors).
- **Paths:** `BatchProof::generate` of their keys at each root. A lone
  path at 10^6 rows has about 21.5 branches.

## 3. Proved and verified on the chain path

### 3.1 Steps and compressions (trace; the derived kernel on `TracingPvm`)

Compressions are the kernel's own, the BLAKE2B chip's rows (96 rows
each). The traced count equals the count predicted from the proofs'
shape in all 12 cases. A row read is one row checked against one root.

| Rows | Journals | Row reads | Args B | Steps | Compressions | **Per row read** | Steps per row read | Segments (32k steps, 8 pages) | Segments (64k, 32) |
|---|---|---|---|---|---|---|---|---|---|
| 10^4 | 1 | 4 | 2,812 | 49,400 | 69 | **17.3** | 12,350 | 2 | 1 |
| 10^4 | 2 | 8 | 5,280 | 88,143 | 133 | **16.6** | 11,018 | 3 | 2 |
| 10^4 | 4 | 16 | 9,782 | 167,134 | 249 | **15.6** | 10,446 | 7 | 3 |
| 10^4 | 8 | 32 | 17,778 | 312,306 | 453 | **14.2** | 9,760 | 12 | 5 |
| 10^5 | 1 | 4 | 3,388 | 55,952 | 85 | **21.3** | 13,988 | 2 | 1 |
| 10^5 | 2 | 8 | 6,288 | 98,811 | 161 | **20.1** | 12,351 | 5 | 2 |
| 10^5 | 4 | 16 | 11,726 | 189,061 | 303 | **18.9** | 11,816 | 8 | 3 |
| 10^5 | 8 | 32 | 21,810 | 358,130 | 565 | **17.7** | 11,192 | 15 | 6 |
| 10^6 | 1 | 4 | 4,108 | 64,110 | 105 | **26.3** | 16,028 | 2 | 1 |
| 10^6 | 2 | 8 | 7,584 | 112,847 | 197 | **24.6** | 14,106 | 5 | 2 |
| 10^6 | 4 | 16 | 14,174 | 216,321 | 371 | **23.2** | 13,520 | 9 | 4 |
| 10^6 | 8 | 32 | 26,130 | 406,342 | 685 | **21.4** | 12,698 | 16 | 7 |

(`SP/runs/trace-all.log`.)

**Breakdown at 10^6 rows, 8 journals (685):**

| Part | Compressions | Per row read |
|---|---|---|
| Branches (two multiproofs of 16 keys, 270 each) | 540 | 16.9 |
| Opened leaves | 32 | 1 |
| Value commitments (176 bytes, two blocks each) | 64 | 2 |
| Key transforms (one per account) | 16 | 0.5 |
| `window`'s `PseudoAccount::of` (2·reads + 1) | 33 | 1.03 |

**Rule of thumb:** compressions per row read ≈ 4.5 + branches per key.
Branches per key ≈ log2(N) + 1.5 − log2(keys in the proof):
- a lone path: 12.5 at 10^4 rows, 16.5 at 10^5, 21.5 at 10^6;
- 16 keys sharing the top of the tree: 9.6, 13.1 and 16.9.

**Where the steps go** (10^6 rows, 8 journals, 406,342 steps;
`SP/runs/profile-n1000000-j8.log`, from the actor's whole program linked
with names and run from the attestable entry, the same step count):

| Steps | Share | Where |
|---|---|---|
| 185,585 | 45.7% | the multiproof walk (`verify_words`): about 171 steps per proof entry, mostly gathering 32-byte hashes from unaligned bytes and packing branch blocks |
| 116,818 | 28.7% | `memcpy`, of which 42,468 copy the 26 KB of arguments in the SDK's decode (1.6 steps per byte), 27,448 move `Account`s, 19,872 copy value bytes into hash blocks |
| 21,588 | 5.3% | `cipher_clerk::settlement::window` |
| 17,056 | 4.2% | decoding the rows (`read_value`) |
| 13,741 | 3.4% | `memset` (zeroing message buffers) |
| 6,850 | 1.7% | the precompile shim, about 10 steps per call |

- **Per compression:** about 593 steps, against the 66-step floor of the
  call itself (core model §11.2).
- **Before and after the hashing:** 44,758 steps before the first
  compression (argument decode) and 4,854 after the last.
- **Byte arrays cost.** A first, byte-oriented cut of the same kernel
  took 492,210 steps at 10^4 rows (50% of them in `memcpy`). Moving
  hashes as `[u64; 4]` and packing branch blocks by shifts brought it to
  312,306 (commit `13f35c2c`).
- **Misaligned access.** The guest target has no misaligned access
  (`"features": "+e,+m"`), although PVM loads take any address. A
  variant built with `+unaligned-scalar-mem` (`SP/actor/unaligned/`)
  takes 291,320 steps at 10^6 rows and 8 journals (−28%), and cuts into
  12 segments instead of 16. compiler_builtins' `memcpy` still takes its
  shifting path there; its `mem-unaligned` feature is not reachable
  through `build-std-features`.

### 3.2 Proving and verifying: 10^6 rows, budget 32,768 steps and 8 pages

The budget is master's production cut (`pvm/proof/docs/plans/roadmap.md:15-19`).
- **Prover:** `canonical_profile_for_bounds` over the windows, then
  `prove_canonical` per window, as `prove_chain` does.
- **Peak RSS** is per segment (`/proc/self/clear_refs` reset before each
  segment), with the full trace resident.
- **Verify** is native `verify_chain_standalone` over the chain, anchored
  at the initial memory root computed from the image.
- **"Boundary"** counts the page-Merkle compressions the BLAKE2B_BOUNDARY
  chip proves for each segment's entering and exiting memory images.

**Poseidon2-M31 channel (format 25), the published channel:**

| Journals | Segments | Kernel compr. | Boundary compr. | Profile | Prove | Per segment | Peak RSS | Proof bytes (bincode) | Verify chain | Verify per segment |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2 | 105 | 879 | 1.5 s | 58.6 s | 29.3 s | 5.4 GiB | 5.20 MB (2.60 MB each) | 0.41 s | 0.20–0.27 s |
| 2 | 5 | 197 | 2,171 | 2.9 s | 115.4 s | 23.1 s | 6.4 GiB | 12.96 MB | 0.55 s | 0.10 s |
| 4 | 9 | 371 | 3,976 | 4.1 s | 203.8 s | 22.6 s | 6.5 GiB | 23.34 MB | 1.09 s | 0.09–0.10 s |
| 8 | 16 | 685 | 6,585 | 6.8 s | 424.6 s | 26.5 s | 6.6 GiB | 41.50 MB | 3.13 s | 0.14–0.25 s |

**Blake2s channel (format 24), for comparison:**

| Journals | Segments | Prove | Per segment | Peak RSS | Proof bytes | Verify chain |
|---|---|---|---|---|---|---|
| 1 | 2 | 6.6 s | 3.3 s | 4.5 GiB | 5.21 MB | 0.09 s |
| 2 | 5 | 24.5 s | 4.9 s | 5.3 GiB | 12.93 MB | 0.44 s |
| 4 | 9 | 71.7 s | 8.0 s | 5.3 GiB | 23.34 MB | 0.62 s |
| 8 | 16 | 97.4 s | 6.1 s | 5.5 GiB | 41.51 MB | 1.04 s |

(Blake2s at 10^4 rows, 1 journal: 2 segments, 5.6 s, 4.3 GiB.)

**Proof size:**
- **bincode:** 2.56–2.61 MB per segment whatever its content.
- **postcard:** 1.97 MB, or 1.44–1.47 MB for a segment with no kernel
  compression (zero openings encode short).
- **Why so large:** the MOBILE PCS (blowup 4, 38 queries). The refine
  path's STANDARD proofs (blowup 16, 19 queries) were 0.55–0.89 MB in S5
  and S5b.

**Poseidon2 against Blake2s:**
- 2.8–8.9× the proving time, about 4.4× on the larger runs (the commit
  runs on the CPU backend);
- 1.2× the memory;
- the same proof size;
- 0.09–0.27 s to verify a segment natively, against 0.03–0.07 s.

### 3.3 The segment budget decides the cost (8 journals, 10^6 rows)

| Channel | Budget (steps, pages) | Segments | Boundary compr. | Prove (+ profile) | Peak RSS | Proof bytes | Verify chain |
|---|---|---|---|---|---|---|---|
| Blake2s | 32,768, 8 | 16 | 6,585 | 97.4 s (+12.1) | 5.5 GiB | 41.5 MB | 1.04 s |
| Blake2s | 65,536, 32 | 7 | 3,851 | 67.1 s (+4.2) | 10.5 GiB | 18.3 MB | 0.52 s |
| Blake2s | 131,072, 64 | 4 | 2,683 | 52.5 s (+5.1) | 15.1 GiB | 10.5 MB | 0.29 s |
| Blake2s, unaligned target | 32,768, 8 | 12 | 5,001 | 54.5 s (+6.1) | 5.4 GiB | 31.1 MB | 0.77 s |
| **Poseidon2-M31** | **131,072, 64** | **4** | **2,683** | **231.6 s (+4.9)** | **17.9 GiB** | **10.5 MB** | **0.46 s** |

**What decides a segment's capacity:**
- **Steps run out before compressions do.** At 131,072 steps a segment
  held up to 343 kernel compressions and 802 boundary compressions in
  18 GiB on Poseidon2.
- **Rows per segment:**
  - at the production cut, 2 row reads per segment for 8 journals
    (32 reads in 16 segments; 2.6 by steps alone);
  - at 131,072 steps, 8 row reads per segment.
- **The boundary is the largest in-AIR cost:** 2,683 to 6,585 page-Merkle
  compressions against the kernel's 685.
  - Each listed page costs two 4 KiB leaf hashes (32 compressions each)
    plus its share of the Merkle paths.
  - A kernel touches about 25 distinct pages: arguments, their heap copy,
    stack, data.
  - Fewer, larger segments therefore cost less in total.

**What 5.5 should take from this:**
- **Within a segment, compressions per row read (21.4 at 10^6) are not
  the binding term.** The binding terms are the steps per row
  (about 12,700, or about 9,100 on the unaligned target) and the
  per-segment page boundary.
- **Leaner kernels pay directly.** A kernel near the call's floor (about
  170 steps per compression) would put the 8-journal window in about
  116k steps, one 131,072-step segment.
- **The profile pass** (`canonical_profile_for_bounds`, which builds
  every window's trace once just to size it) cost 0.9–12 s on top of
  proving.

## 4. Program identity

**What binds the kernel today:**
- **The kernel's bytes.**
  - `derive(elf)` is deterministic per `TRANSPILER_VERSION`
    (`pvm/compiler/src/derive.rs:50`; pinned by
    `pvm/compiler/tests/derive_pinned.rs:14-60`).
  - The agent names the result `ProgramHash::of(blob) = blake2b_256(blob)`
    (`agent/wire/src/ids.rs:62-68`).
  - The install records it per method in `Derivation { program, kernels:
    Vec<(MethodId, ProgramHash)>, transpiler }`
    (`agent/wire/src/records.rs:18-41`).
  - This kernel: `28cff2be…`.
- **The proof's program commitment** is `stark_proof.commitments[0]`, the
  preprocessed-trace Merkle root (`pvm/proof/src/program_id.rs:1-34,
  56-58`). It covers:
  - the decoded instruction per PC (`chips/program_memory.rs:213-…`);
  - the jump table (`chips/jump_table.rs:119-…`);
  - the fixed lookup tables;
  - the heights of the chips that have preprocessed columns;
  - the PCS blowup and hash, through the committed evaluations.

  The Fiat–Shamir domain also mixes the format version and the whole
  `PcsConfig` (`proof.rs:238-254`).
- **One kernel, eight commitments in this spike:**

  | Run | Channel | Commitment | Why |
  |---|---|---|---|
  | 10^4 rows, 1 journal | Blake2s | `ac4dd712…` | MEMORY_PAGE 2^8 |
  | 10^6 rows, 1 journal | Blake2s | `bdba9922…` | MEMORY_PAGE 2^9, BLAKE2B chip 2^13 |
  | 10^6 rows, 2, 4 and 8 journals | Blake2s | `225efd4e…` | BLAKE2B chip 2^14 |
  | 8 journals, 65,536-step budget | Blake2s | `d56835aa…` | every step-driven chip larger |
  | 8 journals, 131,072-step budget | Blake2s | `5a8e6636…` | larger again |
  | 1 journal; 2, 4 and 8; the 131,072-step budget | Poseidon2 | three `P2Hash`es (manifests) | the same three shapes, another hash |

  - The MUL, BITWISE, COMPARE and DIVREM heights differed between 2, 4
    and 8 journals without changing the root. Those chips have no
    preprocessed columns. Their heights are still public, in
    `Proof.log_sizes`.
  - The profile is the observed per-chip maximum over this run's windows,
    "not a proven bound" (`prove.rs:776-778`). So today the commitment
    names (kernel, the run's observed shape, channel). It is not a
    kernel id, and it leaks the run's size.
- **Data and arguments.**
  - **Where they live:** the kernel's read-only and read-write data
    (constants, vtables, tables) are not in the preprocessed root. They
    are in the initial memory image, with the arguments and the zeroed
    heap and stack.
  - **How the proof binds them:** only through `expected_initial_root`,
    which the verifier supplies to `verify_chain_standalone`
    (`verifier/src/lib.rs:786-806`).
  - **The consequence:** a verifier cannot anchor a proof without the
    private arguments. Masking aside, this alone breaks the privacy model
    of the slice 5 plan.
- **Output.**
  - **What is public:** φ7/φ8 (the output's address and length) are in
    the public final registers.
  - **What is not:** the `NetFlow` bytes are only under the final memory
    root. Nothing writes the φ9..12 io-hash (`proof.rs:322-345` reads
    it), so the proof does not yet state the output to a verifier
    without the final image.
- **Witness-independence holds.** `program_commitment_for_profile`
  (`prove.rs:681-712`) recomputes the commitment from the program tables
  and a profile without a trace. The harness asserts this on every proved
  run. The preprocessed generators read only code, bitmask and jump
  table, plus Ristretto comb counts, which a kernel never has
  (derivation refuses 110–114).

**What one id over (derived kernel per `TRANSPILER_VERSION`, preprocessed
root, `ProgramHash`) would take:**

1. **A pinned shape class per kernel.**
   - **What:** a profile fixed from the kernel's declared maxima (steps
     per segment, compressions, pages) instead of observed floors.
     `prove_canonical` already takes forced `min_log_sizes`; the class
     table is new.
   - **Then:** the preprocessed root is a function of (blob, class,
     channel), computable at install from the blob alone. That needs one
     constructor that builds the program tables from
     (code, bitmask, jump table) without a trace;
     `program_commitment_for_profile` takes a `SideNote` today.
   - **Size:** small.
2. **A split of the initial memory root.**
   - **What:** a public data root derived from the blob (data pages,
     zero heap and stack), and a private part: the argument pages and
     5.1's salt page.
   - **The verifier** takes the data root from the id, plus a commitment
     to the private part that the proof binds.
   - **Size:** the real design work. It is 5.1's salt page and public
     input model, and it changes the verifier's anchoring API.
3. **The id itself:**
   `KernelId = H("vos/kernel-id" ‖ TRANSPILER_VERSION ‖ ProgramHash ‖
   class ‖ channel ‖ preprocessed root ‖ data root)`.
   - **Where it lives:** recorded in `Derivation` beside each kernel's
     `ProgramHash`.
   - **Who can check it:** anyone with the ELF can re-derive the blob,
     recompute both roots, and check it.
   - **One per channel:** only Poseidon2 if one channel is published.
   - **Size:** small.

The φ9..12 io-hash (public arguments, output, roots read) is the other
half of the public statement. It is guest code in the derive's prologue
and not part of the id.

## 5. The proof files (for spike 1)

They are at `/home/daniel/.claude/jobs/8e1fc21e/tmp/s5/proofs/`, 103 MB.

**Format:**
- **Channel:** **Poseidon2-M31 channel, `PROOF_FORMAT_VERSION` 25**
  (`pvm/proof/src/proof.rs:181-187`).
- **PCS:** MOBILE: `log_blowup 2`, 38 queries, 20 PoW bits, fold step 1.
- **Encoding:** `vos_pvm_proof::Proof` per segment, in bincode 1.x
  (`*.bincode`) and postcard (`*.postcard`, the settlement-verifier's
  wire format).
- **Commitment:** in `*-seg0.commitment.bincode`, a `P2Hash` of 8 M31.
- **Per run:** a manifest with the profile, the initial and final roots
  and per-segment numbers.

**The runs:**

| Directory | Segments | Notes |
|---|---|---|
| `p2-n1000000-j1/` | 2 | 2.60 MB bincode / 1.97 MB postcard each |
| `p2-n1000000-j8/` | 16 | 2.56–2.61 MB / 1.44–1.97 MB each |
| `p2-n1000000-j8-b131072-64/` | 4 | the largest segment shape: MEMORY 2^20 rows, CPU 2^17, 2.58–2.65 MB / 1.94–2.02 MB each; probably the one to put against the 4 MB rule |
| `b2s-n1000000-j1/` | 2 | Blake2s, format 24, for comparison |

**For spike 1's rule:**
- one segment in postcard (1.4–2.0 MB) is under 4 MB, and at about the
  2 MB unmasked target;
- in bincode (2.6 MB) it is over 2 MB;
- all are well under `max_input` (13.79 MB).

`INDEX.txt` there describes the files and the verifier calls.

## Reproducing

**Builds,** from `SP`:
```
(cd actor && cargo build --release --target riscv64em-vos.json)
(cd harness && cargo build --release)
(cd harness && cargo build --release --features p2 --target-dir target-p2)
```

**Runs:**
```
harness/target/release/s5-kernel-proof gen 1000000 data
harness/target/release/s5-kernel-proof trace actor/target/riscv64em-vos/release/settle-window.elf data/n1000000-j8.args 32768 8
harness/target/release/s5-kernel-proof profile actor/target/riscv64em-vos/release/settle-window.elf data/n1000000-j8.args
systemd-run --user --scope -q -p MemoryMax=24G -p MemorySwapMax=0 nice -n 10 \
  harness/target-p2/release/s5-kernel-proof prove actor/target/riscv64em-vos/release/settle-window.elf data/n1000000-j8.args 131072 64 runs/p2-n1000000-j8-b131072-64
```

The run logs are committed in `SP/runs/*.log`.

## Open points this spike leaves

- **cipher-clerk's `pvm-precompile`:** retarget the feature to
  `vos-pvm-precompiles` (`0x400`). Without it, `window`'s 33 id hashes
  more than double the kernel's steps.
- **A kernel loader and `trace_kernel` in `vos-pvm-proof`;** the
  sparse-memory serving (commit `fb3bf2ac`) to land with it.
- **Step-lean kernels.** The steps per compression, not compressions per
  row, decide segments:
  - word-aligned hashing;
  - no copies of the arguments, since the SDK's decode copies every byte;
  - `+unaligned-scalar-mem` in the guest target (−28%), which needs a
    check that the transpiler and every PVM host accept it.
- **The segment budget for kernels:** larger budgets halve or better the
  boundary cost. (131,072, 64) fits in 18 GiB on Poseidon2.
- **Absence claims** and **space-level anchor roots** are not exercised.
- **MOBILE is hard-coded in `prove_canonical`.** STANDARD would roughly
  halve proof bytes at a higher memory cost; not measured on the chain
  path.
