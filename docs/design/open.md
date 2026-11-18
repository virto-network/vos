# Open: known gaps and next work

The one forward-looking list. Each item names the gap, what is known about
it and where its design lives. The design docs describe what is built;
anything they mark "not built" or "open" is here. This tree holds the
proving and venue items; the node side's items (performance and scale,
identity and privacy, the core model's unbuilt parts) arrive with it.

## Proving

- **The device prover's next levers:** format 47 takes word-level memory
  and the per-program CPU (`proving.md` §8). The per-program CPU for node
  segments is later. The 4-way CPU split by opcode family is not built.
- **The ledgers' padding** [reviewed, 2026-11-10; resolved for device
  proofs by format 47]. `MemoryChip` fixes no place for its padding and
  its sortedness gadget does not fire across a padding row (`both_real`
  zeroes the ordering delta), so its real rows may be several sorted
  runs; every run starts with a `ts = 0` write (`IsGroupStart`, also on a
  padding→real step) and every group ends with a closing read
  (`IsGroupEnd`, also on a real→padding step). A byte is one group, and
  its reads the last write's or its first touch, when its boundary
  produces its `ts = 0` write once. Per ledger:
  - **Segments (41, the AIR 32's leaves verify):** consistent. A byte's
    boundary tuples are its listed page's alone (the CPU's, the
    precompiles' and the witness input's carry 0 in the last field and a
    timestamp ≥ 1, the verifier's `initial_state.timestamp ≥ 1` and the
    chain's entry at 1), and a page is listed once: its 32 aligned rows
    are real together, its leaf `(20, index)` is produced once, and the
    `MerkleNode` balance down from the root's one consumption takes each
    index once. The register ledger: a chain starts only with a register's
    `ts = 0` write (`ChainStartH`), the boundary chip's thirteen, bound to
    the public registers. The program memory is a preprocessed read-only
    table. Padding inside both ledgers is harmless (gates
    `memory_ledger_padding_gate::padding_between_the_ledgers_real_rows_is_harmless`
    and `register_ledger_gate::padding_between_the_ledgers_real_rows_is_harmless`).
    32 and 39 prove the recursion AIR, which has no memory argument.
  - **Device 46:** retired and deleted; its number is never reused. Its
    byte ledger let a byte have two boundary rows, so a read could see a
    byte's first touch instead of its last write.
  - **Device 47 (the word ledger):** consistent. `IsLast` keeps padding
    past the real rows, one sorted run, a word one group; a second
    boundary row's `ts = 0` write has no start to consume it (gates
    `padding_between_real_rows_is_refused`,
    `a_word_touched_twice_at_the_boundary_is_refused`); and the last row
    is padding (`IsLast · (1 − IsPadding) = 0`, degree 2), which removes
    the all-real cyclic trace, every row one word at one sort key with no
    group start (gate `word_ledger_gate::an_all_real_ledger_is_refused`,
    its control that every other constraint holds on it). Its register
    ledger (`DeviceBoundaryChip`'s preprocessed registers, entry at
    timestamp 1) and program memory (preprocessed, read-only) are
    consistent.

  Keeping a byte-ledger format for segments: the word ledger's `IsLast`
  on `MemoryChip` (one preprocessed column and one degree-3 constraint)
  would be a new segment format with its leaf, folds, wrap and pins for
  no soundness gain, so it waits for the next segment format as
  hardening.
- **Segment proving levers** (`proving.md` §9): the 36 cubic gates
  rewritten, narrow BLAKE2b chips, a lighter page boundary or one memory
  argument across segments, and folding device proofs (the recursion
  verifying masked proofs).
- **The cross-space credential:** a credential proven to another space or
  venue (the Poseidon2 root kind, Kreivo's `Credential` handler).
- **The signature chips:** SHA-256 and SHA-512, the bignum chip, and the
  P-256 and Ed25519 drivers, so a device can prove over a hardware key's
  signature instead of a device-held secret.
- **A device format with a heavier interaction PoW:** format 47's is 8
  bits, so well-formed junk ground for 2^8 nonces passes ingress's
  pre-check and costs a decode and the composition (11–27 ms on one x86
  thread) before its 16-bit PoW refuses it; 16 or more bits would refuse
  such junk in about 0.02 ms, at the prover's grind's cost on the phone.
- **`0x402`'s price against its quiet cost:** one native Poseidon2-M31
  compression (`vos_pvm::precompile::poseidon2_compress`) takes 1,925 TSC
  cycles at the median, one BLAKE2b compression 405–414, ×4.65–4.75, on
  one pinned core of an idle machine (load average 0.5), three runs of 31
  rounds of 20,000 [measured, x86 dev machine (Intel Core Ultra 7 155H),
  2026-11-12; a spike outside the tree]. At BLAKE2b's gas a cycle it would
  be about 2,800; `POSEIDON2_GAS` is 3,000, the round price above it with
  headroom [decided].
- **Segment AIR parts not yet under a forgery gate:** the program memory's
  decode binding, the jump table, the lookup tables, the memory page and
  Merkle chips, the witness-input chip, the boundary-binding argument, and
  the segment cut and closing-flag rule (`pvm/proof/SECURITY.md`).
- **Completeness limits:** an invalid dynamic jump cannot be proved; a
  run longer than about 2^27 steps cannot be proved; a BLAKE2b pointer
  within 256 bytes of 2^32 cannot be proved. The 2^27 limit bounds a
  run's length, not only the gap between two accesses to one key: every
  ledger chain of a segment starts at a `ts = 0` write and the ordering
  delta has 28 bits, so no segment whose timestamps pass about 2^27
  proves, and the prover refuses such a run by its step count before
  proving. It is also a soundness bound: the ledgers compare timestamps
  mod p, and the per-segment `ts = 0` anchor bounds every access within
  2^27, so no provable segment reaches the alias 2^30 steps away
  (`pvm/proof/SECURITY.md`, "The leaf's binding"). Lifting it takes a
  wider ordering delta or a per-segment timestamp rebase, a new format.
- **The witness stream's framing:** the AIR binds each witness-input call
  alone (a count at most its capacity, its writes), so a proved run may
  be given a short or empty read and more bytes later; a constraint
  across calls (a zero read final) needs a new segment format. Until
  then a kernel frames its input by content (`pvm/proof/SECURITY.md`,
  "Three boundaries"), and the stock kernels' reads are to be audited
  against that.
- **The leaf's timestamp bytes:** the leaf range-checks the io-hash's 32
  boundary bytes alone, and rests on the fold chain for the rest; a leaf
  alone accepts a `ts_in` whose first limb is `p − 1`. Range-check
  `ts_in`'s 8 bytes in the leaf at the next re-pin (or all 264 unchecked
  boundary bytes, about 3.4k `qm31` rows of the leaf's 28.8k spare
  [estimate]), with a gate: a consistent segment trace whose `ts_in`
  first limb is `p − 1`, accepted by a leaf alone and refused at the fold.
  That gate is a recursion run, and no test builds such a leaf yet.
- **Live fault text:** `ExitReason`'s `Debug` and executor panic messages
  can carry state into logs; the fix is the variant alone and a static
  panic message with its place, checked by one audited run of a faulting
  kernel.
- **The Stwo fork's divergence citation** behind the affine DEEP batching
  of formats 39 and 47 needs a cryptographer's review; format 39's floor
  holds without it (65.33 proven bits, the least term, batched by
  powers).
- **The Blake2b host hook** (`0x400`, Kreivo's `blake2_256`) for the final
  verifier, deferred until a venue's compute weight binds.
- **The segment format's `component_mask`:** format 41's header mixes no
  mask (`pvm/proof/SECURITY.md`'s segment trust boundary); a kernel's
  verifier pins the class, and a chip dropped or added only restricts.
  Mix the mask into the transcript at the next segment format.
- **The statements service's balance:** a registration costs its sender
  core time alone, with no deposit as Kreivo takes, and every item writes
  an outcome and a queue row kept a day while spaces and evidence are
  never dropped, so anyone who buys core time can walk the service to its
  threshold, after which every item's accumulate reverts until the
  operator funds it. What a registration costs the service in bytes is
  unmeasured.
- **The jump-table gate:** the pin and `derive` refuse a program whose
  jump-table entry, static jump or branch lands on no basic-block start
  (`vos_pvm::interpreter::bad_transfer`); no forgery gate yet shows what
  the AIR alone accepts there (a CPU row continuing at the halt address
  through the table), which needs a forged multi-chip trace the gates'
  helpers do not build.
- **The prover's restructures, measured first:** the recursion's circuit
  rebuilt and its constant preprocessed tree committed again for every
  leaf, fold and wrap (`Committed` as the device path keeps it); its trace
  and interaction generation serial and scalar with an allocation a row;
  a statement's segments, leaves and each level's folds proved one after
  another on a global pool of at most 10 threads (an explicit pool and a
  memory-bounded parallel map, in the API); the widest segment chips
  filled one after another on one thread; a class found not to fit by
  generating every chip's trace; the segment cursor cloning the memory
  image for each class attempt. Each changes no proof byte.
- **The verifier's DEEP inner loop** recomputes a per-batch constant for
  every value at every query, in the fork's `accumulate_row_quotients`:
  hoisting it changes no proof or transcript, but it is a divergence on
  the verify path of the fork, for its review and a new pin.
- **One BLAKE2b compression:** the runtime, the precompiles and the
  segment chips' software path each write it, the IV a fourth time;
  exporting the precompiles' one moves the guests' panic locations, so
  every agent program id: at the next re-pin of the node's programs.
- **The runtime's inline tests** (`recompiler/mod.rs`, `refine.rs`,
  `interpreter/mod.rs`, `interpreter/memory.rs`, `gas_cost.rs`) move to
  sibling `tests.rs` files, as the crate's other modules have them.
- **Renames that move blobs:** `final-verifier/src/masked.rs` (format
  39's decode and parameters) beside `masking.rs` (the masked verifier),
  at the next change of the final verifier's circuit.
- **An AUIPC fused with its JALR** (the `call` and `tail` idioms)
  leaves the AUIPC's register unwritten where RISC-V writes it: the
  idiom's scratch (`ra`, `t1`), which compiled code does not read after
  the jump; writing it costs an instruction per tail call.
- **Docs of guest-linked crates:** `vos-abi`'s credentials functions that
  panic on values their callers validate, and `vos-pvm-codec`'s bound of
  a decoded `Vec` by items, not bytes: one line each, at the next re-pin
  of the node's programs.
- **The Blake2s-M31 channel's draws, in the fork:** made uniform (by
  rejection, as the Blake2b channel draws; 0 and 1 are 1.5 times as
  likely per coordinate today) and its doc corrected; a change of 47's
  transcript, so a new device format (`pvm/proof/SECURITY.md`, "Stwo's
  verify path, audited").
- **The lifted Merkle verifier's height-0 tree, in the fork:** its `Ok`
  moved after the shape check; unreachable here, every tree's height
  VOS's own.
- **The fork's PCS caller duties:** `verify_values` taking the DEEP
  coefficient count and the batching mode from its configuration, the
  mode mixed, rather than from the samples alone; VOS's shape check and
  header give both today.
- **Stwo's `hashbrown` requirement** is open (`>=0.15.2`), so a
  workspace whose graph holds a newer `hashbrown` re-resolves Stwo onto
  it: the fuzz targets run Stwo on `hashbrown 0.17.1` (`foldhash 0.2`)
  where the root, the kit and the Wasm blob run it on `0.15.5`
  (`tools/gates/locks.py`'s `DRIFT` names the edge). Bounding the
  requirement in the fork closes it, at its next pin.
- **The interpreter's two loops** share skip and the division, remainder
  and upper-multiply results (`interpreter/alu.rs`); the other register
  results (shifts, rotates, 32-bit arithmetic, the immediate forms,
  comparisons and bit counts) are spelled out in `step` and in the
  predecoded loop, each over its own operand decoding.
- **The kit's lock:** shipping the lock VOS's `check-kit` builds on beside
  the kit, with a command listing every package of the verify graph a
  consumer resolves at another version; and signed release tags with a
  bootstrap that verifies them (without them push access to VOS is the
  trust root).
- **A release-profile proving bench in `pvm/`** (`prove_final` over the
  Poseidon2-M31 kernel, a device prove and verify), so the timings the
  docs quote from the test profile have a reproducible twin.
- **Kreivo's `MaxProofLen`** (`spaces-pallet.md`, the reference mock and
  its vectors) suggests 262,144 bytes where the final verifier refuses
  past `MAX_PROOF_BYTES`, 143,360: a weight charged by the pallet's bound
  pays for bytes no decode accepts. Lower it with the mock and its vectors.
- **The prover's entry points under `pvm/`:** `Program::from_kernel` has
  no caller there (the node side's device install is it), and no test
  holds `tree::prove_run`'s root to a hand-built tree at `cut_class`'s
  cut.
- **Fuzz seeds:** `prove_verify_roundtrip`'s replay seeded from the ISA
  tests' programs (an encoder of its `arbitrary` input), and a halting
  program in `program_blob`'s, so both backends are compared on a
  completed run, not only on refusals and panics.
- **The external audit's scope:** the device shape, the stock kernels, the
  Poseidon2 chip and their masking, with the recursion AIR, the final
  verifier, `derive` and the security tool's counts. Engage before any
  value rides on VOS.

## Execution

- **Host bounds past the Gray Paper's reader** (`vos_pvm_program`,
  `vos_pvm::backend`): a zero-width jump table holds at most as many
  entries as its blob has bytes, a refusal the reader gives as it gives
  an invalid blob's (Ψ's panic, `machine`'s HUH), for any blob, a
  service's under `W_C` among them; and the interpreter prepares at most
  `MAX_INTERPRETED_CODE` (4 MiB) of code, a backend refusal past it, a
  valid program only the JAM-only host's `machine` call can name (a VOS
  host refuses an inner program past 2 MiB first, `inner::budget`). A
  table of implicit zeros (a length, no entries) and a fallible predecode
  lift both.
- **Arithmetic on a code pointer in a register** (`vos_pvm_compiler`):
  the compiler gives a code pointer its jump-table address, so `addi t0,
  t0, 4` then `jalr t0` selects another entry than the source's
  instruction four bytes on. It cannot see the arithmetic: only a
  `jalr`'s own displacement past ±1 is refused, and a source that offsets
  a code pointer otherwise runs differently.
- **Service admission in the node** (`vos_pvm::spi::service_fits`, `W_C`):
  `OuterMachines` refuses a service's code past 4,000,000 bytes; the node
  side's install, and its refine and accumulate answering `BIG`, call it
  when they land.
- **The JAM-only host's inner machines** follow the Gray Paper
  (`inner::Profile::GrayPaper`): a halted or panicked machine keeps its
  funded flag, and nothing bounds the programs they prepare or the pages
  they map, at the text's `machine` and `pages` prices. VOS hosts bound
  both (`inner::budget`); the two erratum drafts (the funded flag, the
  budget) are for the text, until which a host serving untrusted refines
  runs them as a VOS host.
- **The JAM-only host's package** (`JamRefine`): `fetch` kinds 7 and 10
  serve the encoded package and context as the caller gives them; the
  fixture encodes no work package, so nothing holds them to its items.

## Venues

- **Anchoring limits** (`proving.md` §7): a single founding key can squat a
  space's registration at a venue, and one genesis can be registered at two
  venues.
- **The Kreivo leg:** the spaces pallet (`spaces-pallet.md`, with the node
  side) is the teammate's port, built against the verifier kit and the
  conformance vectors; its own open questions are in that doc's §13.
- **Kreivo's retired indices:** the spaces pallet's calls, events, errors
  and statuses keep their holes until the pallet's port compacts them and
  regenerates the conformance vectors.
- **The precompile block** `0x400..=0x4ff` reserved through a JIP.
