# vos-pvm-proof: security considerations

What a verified proof proves about a PVM execution, what it does not, and
which inputs a deployer must supply honestly. It is descriptive, not a
formal argument. The design is `docs/design/proving.md` (§3.6 the
statement, §4 the security levels, §6 the verifiers) and
`docs/design/recursion-air.md`; [`docs/status.md`](./docs/status.md)
lists what the AIR binds per opcode.

Two paths verify in production, and one is a reference:

- **A statement,** a kernel's whole run: its segments (41) verified in
  leaves, folded (32), the root wrapped (39), the wrap verified by
  `vos-pvm-final-verifier` and judged by `vos-statement`. This is what a venue
  (a chain's pallet, the JAM statements service) accepts.
- **A device proof** (47), a device kernel's run, verified natively at a
  node's ingress by `vos-pvm-device` (`Verifier::verify`) against the
  program the node computed from the kernel.
- **A segment proof** (41), verified natively by `vos-pvm-proof-verifier`
  (`verify_standalone`, `verify_kernel_segment`, the chain verifiers): the
  reference the leaf circuit is held to (the recursion's tests), linked by
  no production build; a node verifies segments inside its leaves.

## Formats and their bit counts

Each number names one AIR, one channel and one set of parameters
(`src/format.rs`). Counts are conjectured / proven bits at the format's
reference shape, from the security tool (`src/security.rs`):

| format | proofs | channel | counts | floors | status |
|---|---|---|---|---|---|
| 41 | segments, the shared chip set (the Poseidon2 call among a node kernel's) | Poseidon2-M31 | 104 / 62.81 | 100 / 60 | admitted |
| 32 | leaves and folds | Poseidon2-M31 | 108 / 63 | 100 / 60 | internal (`Status::Internal`): proved and verified inside the recursion, refused by every outside verifier |
| 39 | the final wrap, masked (variant (c)) | Blake2b-256 | 146 / 82.70 | 100 / 80 | admitted: what venues accept |
| 47 | device proofs, masked (variant (c)), `h = 256`, the per-program CPU and the word ledger | Blake2s-M31 | 110 / 62.82 | 100 / 60 | admitted: proven calls at a space's ingress, a device kernel's run each |

- **Conjectured** bits are PoW plus queries times log blowup (the ethSTARK
  conjecture, refuted as stated in 2025; the parameters carry a margin for
  its salvaged form). **Proven** bits are the Johnson-bound count with the
  DEEP, ALI and logup terms. The counts are the tool's own model, pinned by
  the format tests; no one outside has reviewed them.
- **The batch `B`** the count by powers takes is every value the DEEP
  quotient batches, one coefficient each: a column's samples and, for a
  column sampled at two points, the periodicity value the fork adds
  (`deep_values_of_column`); `c`, the most of one column, is counted the
  same way, 3. The segment shape batches 11,091 values; 41's query term
  binds, 62.81. The masked device reference (every device chip at 2^17
  rows) batches 7,470; 47 counts 62.82 by affine batching.
- A verifier rejects a number the registry does not admit
  (`format::lookup`), and a proof on another channel than its format's. The proof's configuration must equal
  the format's. The segment's and the recursion's verifiers count again at
  the proof's own shape and refuse it below either floor. The masked
  formats' (39, 47) count nothing at verify time: their shapes are pinned
  at or under the reference shape (39's fixed layout; a device program's
  log sizes at most `DEVICE_MAX_LOG_SIZE`, which install refuses past),
  and every term of the count is monotone in the shape, so the
  reference's count bounds every proof's (`src/format.rs`'s notes; the
  device format's gates count a cut CPU and a smaller program against the
  reference, `device/tests/device/format.rs`'s
  `the_reference_bounds_the_per_program_cpu` and
  `the_reference_bounds_smaller_programs`).
- **The proven count is the same on every target.** It is taken in `f64`
  (`src/security.rs`) by IEEE 754's basic operations alone: addition,
  subtraction, multiplication and division, each correctly rounded, so
  bit-identical wherever Rust compiles them; comparisons, `f64::min` and
  `is_finite`; conversions from integers, and the saturating cast of the
  count to whole bits; and bit casts. `pow2` builds its power from the exponent's bits and
  `log2` by squaring and halving, with no `libm` call, no square root
  (`√ρ` is a power of two or one times `FRAC_1_SQRT_2`), no fused
  multiply-add (Rust never contracts one) and no NaN on an admitted shape.
  The targets the verifiers build for (x86-64, aarch64, `wasm32`, and
  `thumbv7em` and the PVM guest, whose `f64` is software) all round so;
  only an x87 FPU (an `i586` target) would not, and nothing builds for one.

**End to end, the proven bound is the weakest inner format's: 62.81 bits,
not the wrap's 82.6.** Forging a leaf's segment forges the statement. The
conjectured bound is 104. Under Grover's heuristic that is about 31 proven
and 52 conjectured bits against a quantum prover: post-quantum readiness
rests on the conjectured count.

## The segment AIR

- **Hardened by audit.** An audit of the AIR in four parts (the CPU and
  the register ledger; memory, page permissions, the root boundary and the
  host verifier; arithmetic; BLAKE2b) found holes that the tamper tests had
  not. Each was fixed only after a forgery gate, a consistent forged
  trace, was written and accepted by the unfixed AIR; the gates stay as
  tests (`tests/gates/*_gate.rs`).
- **Not yet under a forgery gate of that kind:** PROGRAM_MEMORY's decode
  binding, JUMP_TABLE (one padding fix), the lookup tables, MEMORY_PAGE and
  MEMORY_MERKLE, the witness-input chip, the boundary-binding argument
  (the boundary states recomputed into the boundary chips' claimed sums),
  the segment cut and closing-flag rule. These are in the
  external audit's scope (below).
- **Recorded, unfixed:** an invalid dynamic jump cannot be proved (no
  kernel needs it); the ledgers cannot prove a gap of 2^27 steps between
  two accesses to one key; a BLAKE2b pointer within 256 bytes of 2^32
  cannot be proved. Each makes an honest run unprovable, never a false one
  provable. The 2^27 gap is also a soundness bound: the ledgers compare
  timestamps mod p, and it is what keeps two accesses 2^30 steps apart
  from aliasing (the leaf's binding, below).
- **The Ristretto and scalar chips are removed:** they were unsound.
  Precompile ids 110 to 114 are served nowhere, and `derive` refuses a
  kernel that reaches one.
- **The witness input (`0x401`)** is a kernel's only argument channel:
  CpuChip binds the call's destination, capacity and count (at most the
  capacity, written to φ7), and WitnessInputChip writes each byte to the
  memory ledger at the call's timestamp, the addresses a carry chain that
  cannot wrap past 2^32. The register ledger orders reads before writes in
  a step, so a call cannot read its own result. What a kernel read is the
  `witness_input` of its attest. The live host returns `min(capacity,
  remaining)` bytes (`src/core/ecall.rs`); the AIR binds only the count's
  bound, so a proved run may return a short read and then more bytes,
  which no live stream does. A kernel must not take a short read for the
  end of its input.
- **The Poseidon2 call (`0x402`)** computes `C(l, r)`, the width-16
  permutation of `l ‖ r` truncated to 8 words, with no feed-forward: a
  pseudo-compression, a preimage of any digest one inverse permutation
  when both inputs are free. It is safe in a fixed-depth tree over sponge
  leaves, or a chain from a fixed tag with a length block (`H_io`), and
  not as a general two-input commitment: a kernel must not commit to a
  pair of free values with one call.
- **The halt rule:** a halting step's `next_pc` is `PVM_HALT_ADDR`
  (2^32 − 2^16), which no static jump, branch or jump-table entry of a
  pinned program names: `kernel::kernel_side_note`, which every install's
  pin starts from, refuses a program any of whose control transfers lands
  on no basic block start (`vos_pvm::interpreter::bad_transfer`), the halt
  address among them, as `derive` does. The AIR checks only that a next pc
  is an instruction start, so the refusal is what keeps a proved run to
  the transfers the machine takes, and a segment ends at that pc exactly
  when it ends at a halt. A trap keeps `next_pc = pc`: a panic cannot
  present as a halt. At the halt φ9..12 hold the io-hash.
- **No gas is proved.** A statement says nothing of a run's cost: the live
  host meters, and live ≡ traced holds for the runs the host completed.
  The prover role bears the cost of a run it chose to prove.
- **Page permissions are part of a program's identity.** A kernel's
  regions (read-only data and the argument window readable; read-write data,
  heap and stack writable; nothing else mapped) are preprocessed constants
  of MemoryPageChip, so they enter the preprocessed root: a store to a
  read-only page, or an access to an unmapped one, does not prove.
- **No chip-isolated proof verifies standalone:** a proof with
  `component_mask = 0` (the explicit-components test path) names no
  boundary chips, and `verify_standalone` refuses it before any
  cryptographic work, as it refuses a mask outside this AIR's chips or
  whose popcount is not the component count.

## Trust boundary: a segment proof

| input to `verify_standalone(proof, hash)` | trusted? | |
|---|---|---|
| `proof.format_version` | no | an admitted number, on its format's channel |
| `proof.interaction_pow` | no | checked against the format's bits before any relation challenge |
| `proof.stark_proof` | no | verified by Stwo, after a hostile-input preflight of every nested length |
| `proof.claimed_sums` | no | must sum to zero; the boundary chips' must equal the sums recomputed from the boundary states |
| `proof.log_sizes` | no | capped by `DEFAULT_MAX_LOG_SIZE`; no public verify entry takes another cap (only the bare preflights, `proof::preflight_proof_structure` and `proof::preflight_proof_structure_readonly`, do) |
| `proof.initial_state`, `proof.final_state` | bound | registers, pc and ts bound to the committed boundary columns and to the trace, both ts in `[1, 2^28)` (`TIMESTAMP_BOUND`); `memory_root` to the in-AIR page tree of the images |
| `proof.pcs_config` | no | the format's exactly; Fiat–Shamir-bound |
| `proof.component_mask` | no | the chips it names: within this AIR's, its popcount the component count. Format 41's header mixes no mask: a kernel's verifier pins it to one of its shape's classes (`class_of`), and the leaf's constants pin it; in bare `verify_standalone` it is the prover's, and dropping or adding a chip only restricts the traces that verify |
| `hash`, the preprocessed root | **yes** | the class's program identity: its code, layout and permissions, at its shape. For a kernel, the install's record derives it, and the program id covers it |

The preflight, the format checks, the boundary timestamps' range, the root
against `hash`, the logup sum, the boundary binding, then Stwo's verifier,
in that order. The checks are written once (`src/standalone.rs`); the
prover-side `vos_pvm_proof::verify` runs them at the root it commits again
from its side note.

## Trust boundary: a statement

- **The wrap's verifier pins its own circuit.** `vos-pvm-final-verifier`
  holds the wrap's preprocessed root, its log sizes and format 39's
  configuration as constants (the DEEP batching from the format, never
  from the proof). It refuses bytes over 256 KiB, a non-canonical or
  trailing encoding, and a proof whose shape (trees, samples,
  decommitments, queried values, every column's samples against its
  component's mask) is not the wrap's, all before any Stwo call. It mixes
  the 24 public words (the program id, the io-hash's 16 limbs) before the
  interaction PoW and checks the logup sums with their public terms.
- **What an accepted wrap proves:** a run of the program the id names,
  from its entry state (the kernel's entry pc, ts 1, the loader's
  registers, the image root) through contiguous segments of that
  program's classes to a halt, with that io-hash at the halt. Leaves
  re-do the native verifier's checks in circuit; every fold checks
  adjacency, state continuity and that both children carry the program id
  it recomputes and the fold circuit's hash; the wrap pins that hash and
  refuses a root without position 0, the entry and the halt.
- **The program id is the trust anchor.** A Poseidon2-M31 hash over the
  transpiler version, the program hash, the shape, the segment channel,
  the classes' preprocessed roots, the image root and the leaf circuits'
  hashes. A venue verifies against the id **it pinned** for the kernel
  whose handler acts, by governance, never against the statement's or the
  proof's: otherwise any kernel's proof would do. Anyone with the
  recursion stack recomputes the id from the kernel and its install record.
- **Admitting a program id is admitting an audit of that kernel.** No
  layer checks that a `RootRead` the kernel states is the root its
  multiproof was checked against, that it carries a nonce where its
  statements may repeat, or that its low-entropy outputs are salted: only
  the kernel's code does, and the id pins that code. "Program intent"
  below applies to kernels in full.
- **The statement id** is `BLAKE2b-256("vos/statement/v1" ‖ program ‖
  space ‖ io_hash)`. A venue refuses an id it has accepted, and keys on it,
  never on a proof's bytes (one proof has many encodings, and many proofs
  state one statement). The id does not hash the final format: one run
  wrapped under two formats during a transition is one statement.
- **Rooted statements alone.** Only a root binds a statement's space: the
  proof states none, so a rootless statement's space would be whatever its
  submitter writes, and one accepted proof could be applied at every
  venue. `judge` refuses a statement of no root, and one claiming
  `SpaceId::NONE`. The io-hash covers the roots, so the proof binds them.
- **Bound to a venue by the space's discipline.** A rooted statement is
  accepted only where its space's roots are anchored: at the venues its
  space registered at. A space anchors at one venue for good, but nothing
  at a venue sees another: a genesis registered at two venues makes each
  accept the same statement (same roots) or forks the space unseen
  (different roots). An anchor gives ordering and non-equivocation, not
  integrity, so a value-moving handler is two-sided or spends the
  submitting space's own escrow.
- **Every re-pin is a governance event.** A segment format bump (any
  hardening of the base AIR) changes every program id; a change to the
  recursion's compiler or gates changes every leaf circuit's hash, the fold
  circuit's hash and the wrap's pinned root.

### The leaf's binding: two inductions

A leaf re-does the native verifier's checks in circuit, over the boundary
states' 296 bytes as wires. Two properties every statement rests on hold
along the fold chain, not in a leaf alone (`recair/src/leaf/mod.rs`):

- **The boundary bytes are bytes.** The leaf range-checks 32 of the 296
  (the io-hash's); a wire of 256 or more would enter the segment AIR as a
  register, a timestamp or a root limb no native state can express. The
  leftmost entry is byte constants (the entry flag, which the wrap
  requires), every exit equals the next entry wire for wire (the fold's
  continuity), and an exit is bytes the AIR produced (the next timestamp's
  and a register write's limbs Range256-checked, a memory root the
  BLAKE2b boundary compression's output, an XOR of byte pairs the bitwise
  table fixes, the chip under `blake2b_boundary_gate`) or
  a copy of its entry.
- **Timestamps stay in the ledgers' range.** The register and memory
  ledgers compare `2·ts + is_write` reduced mod p, so two accesses about
  2^30 steps apart alias; no gas is proved and the CPU's timestamp is a
  64-bit counter. Every chain of a segment starts at a `ts = 0` write, so
  a segment whose timestamps lie in `[2^27, p/2)` is unprovable, and a
  run, contiguous from ts 1, cannot cross that zone. The native verifier
  states the bound for a segment alone (both boundary timestamps under
  2^28); the leaf does not range-check the timestamp's bytes, and a leaf
  alone accepts a first limb of `p − 1`, which the fold chain then cannot
  continue from an honest entry. Range-checking `ts_in`'s bytes in the leaf
  is recorded for the next re-pin (`docs/design/open.md`).

## Trust boundary: a device proof

`vos_pvm_device::Verifier::verify(io, bytes)` (`device/src/verify.rs`),
which a node runs natively at ingress on bytes a caller submits:

| input | trusted? | |
|---|---|---|
| the `Verifier`: the program, its masked format and its id | **yes** | computed by the node from the kernel and its release (`Program::from_kernel`, then `Program::verifier`): its chips (what its code can reach, `device_chips_of_code`), its CPU cut (`CpuColumns::of_code`), a log size each (its reference run's, raised by the headroom), its layout and the preprocessed root those commit; the format looked up by its number in `FORMATS`. Never read from a proof |
| `io`, the io-hash | **yes** | computed by ingress from the claim it holds (`claim_io`: `H_io` of the claim's bytes, no output, no root), never the proof's |
| `bytes` | no | at most `MAX_PROOF_BYTES` (1.5 MiB), then checked as below |

**The order of its refusals:** `precheck` (the length; the leading fields
read; the format number the program's; the interaction PoW over the
header, the program's chips, the first two roots and `io`, as the
transcript mixes them), then the decode (postcard, canonical: re-encoded to
the same bytes, nothing after it), then `verify_masked` under the
program's pinned masked format: the shape before any Stwo call, the
preprocessed root the program's, the claimed sums cancelling and
DeviceIoChip's the one `io` fixes, then Stwo's `verify_values`. Each maps
to one `Refusal`.

**What an accepted proof proves:** a run of the program's code, from its
entry (timestamp 1, pc 0, the layout's registers) to its halt pc, its
first touches the layout's (the data table, zero stack and heap, nothing
else), no write landing on a read-only region, with the io-hash `io` in
φ9..12 at the halt. Every other register and every value of the run stay
masked (§ Masking).

**The CPU cut:** a program's CPU is the full CPU's AIR with the columns its
code never sets fixed to zero, and the constraints and fractions that
vanish under that cut dropped (`src/chips/cpu/cut.rs`): every cut trace is
a trace of the full AIR, so the cut proves no statement the full CPU does
not. The code binds the cut (an instruction's flags are its code's, by the
program memory's lookup), and the cut enters the program's id and its
transcript. The pin code that decides it (`src/chips/cpu/cut/pin.rs`,
`src/device/pin.rs`) is in the audit's scope. A test evaluates the full
AIR at random points with the cut columns zero, over each opcode's,
each precompile's and random programs' cuts and random column sets, and
finds every dropped constraint and fraction numerator zero.

**Columns bound by tuple equality alone.** A few columns are never range
checked themselves: the word boundary's `Initial` and `Last`,
DeviceBoundaryChip's `FinalValue`, DeviceIoChip's `Value`, and the word
ledger's `Address`, `Value` and `Timestamp`. Each is bound only by the
relation tuples it shares with another chip: the data table's
preprocessed words and the ledger's first and closing rows, the register
ledger's closing read, the io-hash words the verifier fixes from `io`, the
accesses the CPU and the precompiles produce. Below `p` fractions a
relation, logup forces those tuples to match as multisets, so each such
column holds a value its counterpart bounds; a change to a counterpart's
own checks is a change to these columns' soundness.

**A panic is a refusal, not a crash:** the device crate runs with std and
is not linted panic-free; ingress catches a verifier's panic and counts it
a failed proof (`node/host/src/credentialed.rs`'s `verifies`). The fuzz
target `device_verify_bytes` holds it to no panic on arbitrary bytes.

**The interaction PoW is 8 bits:** well-formed junk ground for 2^8 nonces
passes `precheck` and costs a decode and the composition (11–27 ms on one
x86 thread) before the PoW refuses it (`docs/design/open.md`).

## Panic-freedom

A FRAME runtime cannot catch a panic (no unwinding on wasm32 without std;
a panic aborts the block's import), so no guard can wrap the verifier. The
five crates the kit vendors (the final verifier, `vos-statement`,
`vos-anchor`, `vos-pvm-recair-air` and `vos-pvm-poseidon2`) must be
panic-free on every input by construction:

- **The crates' own code:** outside their tests, `clippy::unwrap_used`,
  `expect_used`, `indexing_slicing`, `panic`, `arithmetic_side_effects`,
  `unreachable`, `todo` and `unimplemented` are denied
  (`#![cfg_attr(not(test), deny(..))]` in each `lib.rs`, and in the
  venue's JAM program's bin and the Wasm blob, which `just
  check-no-std` lints for their targets). Each allowance is in place with
  its reason: QM31's modular addition (the logup sums, twice), the
  compact's big-integer mode (`width` 4 to 8 once checked), `vos-statement`'s
  `fixtures` reader (the harnesses', std, never a venue's), the JAM
  program's allocator (sums of `Layout` sizes and arena offsets); in
  `vos-pvm-recair-air`, the constraint bodies' field arithmetic and their
  fixed-size arrays indexed by the layout's constant offsets, the circle
  group's addition, a format's masking's few columns summed, the wrap
  layout's reserved wires, and `Rebound`'s preprocessed indices (below
  the preprocessed tree's width, which `sample_points` checks); in
  `vos-pvm-poseidon2`, M31's arithmetic (each operation's bound in its
  reason), the permutation's fixed 16-word state, the sponge's buffer
  (below `RATE`) and the tables built when the crate compiles; its
  `packed` module, the prover's alone, is allowed whole. No lint covers
  `assert!`: outside their tests the crates hold `M31::new`'s, whose
  callers pass constants and 16-bit limbs, and three `debug_assert!`s,
  compiled out of a release build, in `vos-pvm-recair-air`'s `p2.rs` (the
  body's selector loop over `P2Mode::ALL`, which holds no tagged mode, and
  the prover's trace generator). `split_at` and
  `copy_from_slice`, which no lint covers either, appear at lengths equal
  by construction (`codec.rs`'s big-integer mode; a digest's eight words
  into a 16-word state).
- **Stwo's code at the pin:** every index, `unwrap`, `expect`, `zip_eq`,
  `assert` and unchecked arithmetic reachable from format 39's
  `masking::verify_masked` (its `replay`, then `verify_values`) is in the
  table below with what guards it. Two had no guard and are the fork's fix
  (DIVERGENCE-013).
- **Fuzzing:** eight targets (`fuzz/`, the justfile's
  `proof_fuzz_targets`): the final verifier on arbitrary bytes
  (`final_verifier_bytes`), on the golden wraps mutated
  (`final_verifier_mutate`), on format 39's layout past its header
  (`masked_bytes`) and on its queried parts reshaped (`masked_shape`); the
  statement's decoder and the venue's check (`statement_decode`); the
  anchor's decoders (`anchor_decode`); prove-then-verify on random
  programs (`prove_verify_roundtrip`); and the device verifier on ingress's
  bytes (`device_verify_bytes`). A checked-in corpus is replayed by `just
  gate` (`just fuzz-replay`), and `just fuzz` runs a minute a target in
  `ci-full` and five in the full gate (`just slice-gate`).

### Stwo's verify path, audited

"Shape" is the verifier's check before any Stwo call: format 39's
`check_shape` and `samples_fit` (four trees of commitments, sampled values,
decommitments and queried values; each tree's sampled and queried columns
its pinned width; each column's samples its sample points; FRI's inner
layers its rounds; the last layer `2^6`; every limb canonical), and its
fixed layout's pins and bounds. "Ours" is a value the verifier
computes from the format, never read from the proof.

| # | site (`crates/stwo/src/core/…`) | guard |
|---|---|---|
| 1 | `air/components.rs` `mask_points`: `mask_points[0]`, `preprocessed_mask_points[idx]` | ours: the circuit's preprocessed indices, below the preprocessed tree's columns the verifier committed |
| 2 | `eval_composition_polynomial_at_point` → `constraint-framework` `evaluate_constraint_quotients_at_point` through `vos-pvm-recair-air`'s `Rebound`, over the layout's columns: `mask[0][idx]`, `sub_tree`'s `assert_eq!` and `get_chunk().unwrap()`, `PointEvaluator::next_mask`'s `mask[interaction][col_index]`, `assert_eq!(mask.len(), N)`, `try_into().unwrap()` | shape: each tree's sampled columns and each column's samples the components' masks (`check_shape` + `samples_fit`) |
| 3 | the same: `coset_vanishing(..).inverse()` | z on the QM31 circle at a point of the trace's coset: about 2^-108 a draw, no grinding reaches it |
| 4 | `circle.rs` `get_random_point`: `(1 + t²).inverse()` | t = ±i: 2^-123 a draw |
| 5 | `pcs/verifier.rs` `commit`: `log_size + log_blowup_factor`; `vcs_lifted` `MerkleVerifierLifted::new`'s `assert!` | ours: the trees' log sizes and the format's configuration, no lifting log size, so the height is the tallest column |
| 6 | `verify_values`: `zip_cols` (`zip_eq` trees, `zip_eq` columns) of sample points × sampled values | shape: four trees, each tree's columns and each column's samples |
| 7 | `verify_values`: `trees.last().unwrap()`, `trees[0].height`, `lifting_log_size − log_blowup_factor` | ours: four trees committed by the verifier, each at least the blowup tall |
| 8 | `pcs/utils.rs` `prepare_preprocessed_query_positions`: the shifts | ours: the trees' heights (the preprocessed tree's 21, the tallest 22) |
| 9 | `verify_values`: `zip_eq` trees × decommitments × queried values × query positions | shape: four decommitments and four queried trees |
| 10 | `vcs_lifted/verifier.rs` `verify`: `col_vals[idx]` | the fork's `QueriedValuesShapeMismatch` (`ca20894`) first: one column a committed column, one value a query |
| 11 | `verify`: `chunk[0]`, `chunk[1]`, `unreachable!` on `idx & 1` | `chunk_by` yields non-empty runs of at most a sibling pair |
| 12 | `verify`: the root layer's `try_into().unwrap()` | ours: the positions drawn below `2^height` (tree 0's mapped into its height), 24 of them, so one root remains; a witness too short or long is an error |
| 13 | `pcs/quotients.rs` `fri_answers`: `assert!` every queried column one value a query; `col[idx]` | every tree's Merkle `verify` (10) passed first, tree 0's on as many positions |
| 14 | `build_samples_with_randomness_and_periodicity`: `expect(ONE_COEFFICIENT_A_VALUE)` | ours: the affine coefficients drawn by `n_deep_values` over the same samples (powers are unbounded) |
| 15 | `accumulate_row_quotients`: `queried_values_at_row[column_index]`; `zip_eq` of a batch's columns × its line coefficients | shape: the sampled columns (whose indices these are) and the queried columns both the trees' widths; the coefficients built from the same batch |
| 16 | `constraints.rs` `complex_conjugate_line_coeffs`: `assert_ne!(z.y, conj(z.y))` | **none at the pin**: Im(z.y) = 0, about 2^-62 a draw, z grindable. The fork's fix: `InvalidStructure` (DIVERGENCE-013) |
| 17 | `denominator_inverses` → `CM31::batch_inverse` → `inverse()`'s zero `assert!` | **none at the pin**. The fork's fix: `InvalidStructure` (DIVERGENCE-013). Unreachable for z on the circle with Im(z.y) ≠ 0: the line vanishes at a base-field circle point only if Im(z) is isotropic, which no circle point's is (proved in its doc) |
| 18 | `fri_answers`: `lifting_domain.at(bit_reverse_index(position, ..))` | ours: positions drawn below `2^lifting_log_size` |
| 19 | `fri.rs` `FriVerifier::commit`: `CanonicCoset::new(..)`'s `try_new().unwrap()`, `LineDomain::new`'s `assert!`, `n_inner_layers − 1` | ours: the degree bound from the verifier's tallest tree (22 − 5); the subtraction only inside the loop over the layers; a wrong layer count is `InvalidNumFriLayers`, a last layer of another size `LastLayerDegreeInvalid` |
| 20 | `FriConfig::new`'s `assert!`s; `draw_queries`' `(1 << log_size) − 1` and `try_into().unwrap()` | ours: the format's configuration; `u32` into `usize` |
| 21 | `decommit`: `expect("queries not sampled")` | sampled in the same `verify_values` |
| 22 | first and inner layers' `verify`: `assert_eq!(queries.log_domain_size, ..)`; `Queries::fold`'s `assert!` | ours: the queries drawn on the first layer's domain and folded by the steps `commit` derived |
| 23 | `compute_decommitment_positions_and_rebuild_evals`: `subset_queries[0]`, `query_evals.next().unwrap()` | non-empty `chunk_by` runs; one evaluation a query (`fri_answers`' one a position, then the folds' one a folded query); a short witness is an error, a long one too |
| 24 | `SparseEvaluation::new`'s `assert!`s; `fold_circle`'s `assert!`, `buffer[0]`, `fold_step − 1`; `fold_line`'s `assert!(n ≥ 2)`, `eval[j]`; `fold_circle_into_line`'s `dst[i]` | ours: subsets of `2^fold_step` built just before, fold step 3 |
| 25 | `build_merkle_verification_inputs`: `next().unwrap()`, `merkle_values[..]`; `domain.log_size() − leaf_log_size` | ours: one value a decommitment position, whole subsets of `2^3` ≥ a packed leaf of `2^2`; packing only on domains of at least `2^2` |
| 26 | `decommit_last_layer`: `zip`, `LinePoly::eval_at_point` | the last layer's `checked_log_size` in `commit` (and 64 coefficients pinned) |
| 27 | `fold_line`'s and `fold_circle_into_line`'s twiddle inversions (`x.inverse()`, `p.y.inverse()`) | ours: points of canonic cosets (y ≠ 0: y is 0 only at points of order at most 2) and of their line domains (x is 0 only at order-4 points, a domain of 2; FRI stops at the last layer's domain, at least 2^7) |

Field inversions elsewhere on the path (M31, QM31) are only 3, 4, 17 and
27, and VOS's own: `vos-pvm-recair-air`'s `public_logup_sum`
(`recair-air/src/gate.rs`, called from `final-verifier/src/masked.rs`)
inverts each public term's `Gate` denominator, 25 on the wrap, and
`QM31::inverse` asserts non-zero at the pin; a denominator is zero with
probability about 2^-124 a term, over challenges drawn after the main
root. The device path has the same shape in DeviceIoChip's recomputed sum
(`src/chips/device_boundary.rs`'s `io_claimed_sum`, 4 terms, φ9..12).
The channel's draws and `verify_pow_nonce` index nothing from the proof.

### The corpus

`fuzz/replay/<target>.tar` holds each target's corpus, one archive
(`fuzz/corpus.py`: sorted names, no times or owners, so the same inputs
are the same bytes), rebuilt by `just fuzz-refresh` (seeded from the
goldens, fuzzed, merged to the inputs that add coverage) and pruned to
what a verdict needs, a whole proof kept only where no smaller input
reaches it; `just fuzz-replay` (in `just gate`) unpacks the archives into
`fuzz/target/replay/` and runs every input once, and `just fuzz-reach`
(in `gate` too) holds what the corpus reaches to `fuzz/reach.txt`, which
`cargo run --example paths` writes. It reaches:

- format 39 by bytes (`final_verifier_bytes`, `masked_bytes` past the
  golden's header): the format word, the decode, non-canonical encodings,
  the shape before any Stwo call (four commitments, four decommitments,
  four trees of sampled and of queried values, a tree's sampled columns, a
  count over its bound), and, on whole proofs, the circuit, the
  interaction PoW, the logup sums, a Merkle root and the golden accepted;
- 39 mutated (`final_verifier_mutate`): the format, non-canonical
  encodings, the circuit, the interaction PoW, the logup sums, the shapes
  (four trees, a column's samples, a tree's queried columns, FRI's
  layers), OODS, PoW, Merkle (queried-value shape, root, witness short and
  long), FRI (first and inner layers' evaluations and commitments), and
  mutations that cancel, accepted;
- 39 reshaped (`masked_shape`): non-canonical encodings, Merkle (shape,
  root, witness short and long), FRI's first and inner layers'
  evaluations and commitments, and accepted;
- the venue (`statement_decode`): a short or non-canonical statement, the
  format, the program, the space, an unanchored root, a repeat, the
  proof's decode, format, non-canonical encoding and shape, and the golden
  accepted;
- the anchor (`anchor_decode`): each decoder's short, non-canonical and
  trailing inputs, and a decode;
- the device verifier (`device_verify_bytes`): an input shorter than an
  io-hash, the decode, the format, the interaction PoW pre-check, and an
  honest proof accepted.

Not covered: FRI's last layer (its evaluations; its degree, which the
layout holds), the device verifier past its pre-check on a malformed
proof (its masked verify is 39's, which the targets above reach), and
the two degenerate DEEP lines (the fork's unit tests).

## The Stwo fork's open divergences

The workspace pins olanod/stwo at `e14925a8` (`vos/neon-compress16`:
Blake2s's 16-lane compression run as four NEON groups of four on
aarch64, its words unchanged, on `vos/simd-m31-reduce`'s `9e9b4ff6`: the
SIMD backend's Blake2s-M31 digest words reduced canonically over the whole
u32 range, as the verifier reduces them, on `vos/grind-chunks`' `4cd1f83f`:
the prover's parallel grind in chunks of 2^14 nonces, its nonce unchanged,
on `vos/verify-panics`' `c3ec9813`, on `vos/wrap`'s `ab294189`). Its divergence
log, in the fork's tree at the pinned revision
(<https://github.com/olanod/stwo/blob/e14925a81606b4d68c6a5d3047d382a20bd953d3/.claude/skills/paper-implementation-divergence-log.md>), holds two
open items both wraps' counts rest on, and one the verifier's
panic-freedom does:

- **DIVERGENCE-013:** the DEEP quotient's degenerate lines refused, not
  asserted: `complex_conjugate_line_coeffs` and `denominator_inverses`
  return `VerificationError::InvalidStructure` where upstream panicked (a
  sample point whose `y` is its own conjugate; a conjugate line through a
  queried point), each with a unit test from a constructed point. The
  accepted set is unchanged. Branch `vos/verify-panics` (`c3ec9813`), on
  `ab294189`, under the pin.
- **DIVERGENCE-011:** the first FRI round folds by `2^fold_step`, the
  circle fold in it. The security tool counts it so; a model counting the
  circle fold as its own round would differ by about 0.8 bits on the fold
  term. Format 39's FRI tests `2^17`, so its rounds are `[3, 3, 3, 2]` to
  the `2^6` last layer; its fold term sits 0.19 bits
  above its batching term (82.98 against 82.79). Under the other model the
  fold term would bind first, at about 82.2, still above 80. The round
  list the tool counts must equal the one the fork's `FriVerifier::commit`
  derives from the largest column.
- **DIVERGENCE-012:** affine DEEP batching, opt-in per format (39),
  counted as `ε_lin(k)` by BCIKS20 Theorem 1.6. soundcalc calls it *linear
  batching* (`pcs.py`'s `_get_batching_error`, `johnson_bound.py`'s
  `get_error_linear`) and cites only BCHKS25; the BCIKS20 names are ours,
  so the audit checks that Theorem 1.6's correlated agreement for affine
  spaces carries BCHKS25 Theorem 4.2's improved `ε_lin`. It carries the
  wrap from 76.98 to 82.70 proven bits, and needs a cryptographer's review
  of the citation and the count: if it is wrong, the wrap is at 76.98,
  below its 80-bit floor (the end-to-end bound, 62.81, is the inner
  formats' either way).
  - **What it holds:** batched by powers, the batching term caps 39 at
    76.98 (74.48 at blowup 64), at its 538 batched values, and at blowup
    64 with 20 queries under masking that term is the one that binds
    (81.74).
  - **Its premise in the masked transcript:** every batched function, the
    masked columns' quotients, the FRI mask's and the blinding columns'
    among them, is committed and every sample mixed before the affine
    coefficients are drawn; the masked verifier takes the batching from
    the format, never from the proof.
  - **If it falls,** format 39 needs a new number: a batching-phase PoW of
    at least 4 bits at blowup 32 (6 at blowup 64), or blowup 8 with 41
    queries (about twice the verify).

## Masking

Format 39's wraps and format 47's device proofs are masked, over one
masked verifier (`final-verifier/src/masking.rs`, the device's component
set laid out as its program pins it); segment, leaf and fold proofs are
unmasked:
their witness (digests, positions, the io-hash, the fold word) and their
trace are in the clear, and they must never leave the prover role.

**Format 39,** the masked wrap, is admitted: `vos-pvm-recair-air`'s masked
AIR, `vos-pvm-recair`'s masked prover and `vos-pvm-final-verifier`'s masked
verifier (the masked transcript below, every parameter the format's, the
shape checked before any Stwo call), its bytes a fixed layout with one
encoding a proof.
The verifier leaves three facts to Stwo, each pinned and tested: the
trees' widths `verify_values` zips; the FRI rounds `FriVerifier::commit`
derives from the largest column (`[3, 3, 3, 2]`); and FRI's degree bound,
the last committed tree's height less the blowup (17), so the composition
tree is the last and tallest commitment.

**The masked transcript,** prover and verifier alike, in this order: the
header (format 39's number and configuration); the preprocessed root
(unsalted); the main root (each component's masked columns, then its
blinding columns, then the salts); the 24 public words; the interaction
PoW; the `Gate` relation, then `BlindRelation`; the blinded claimed sums;
the interaction root (masked, salted); the composition coefficient; the
composition tree (the whole composition, the FRI mask `R`'s 8 columns,
salts); the OODS point `z`, each component sampled at its own level, the
composition at `π(z)`, `R` at `z`; then the affine DEEP coefficients,
drawn after every commitment and every sample is mixed; FRI; the PoW; the
queries. The verifier never calls `stwo::core::verifier::verify` (its
composition split is hardcoded, DIVERGENCE-004): it runs over the
commitment scheme's `commit` and `verify_values`.

**Variant (c).** Every main and interaction column is masked,
`f' = f + v_H·r` with `r` of `h` uniform coefficients, so its degree bound
is `2N` for a tallest component of `N` rows; the composition, of bound
`4N`, is committed whole, never split. The masked columns are lifted one
doubling more than the quotients, so the AIR is evaluated at level `m+1`
and the composition is sampled at `π(z)`. A cubic constraint's masked
quotient fits `2N` while `h ≤ 2N/3`; `h ≤ N/4` covers quartic too. What
(c) adds to soundness: the `4N` composition bound doubles the DEEP-ALI
error, and `π(z)`, uniform on half the circle, doubles it again; lifting
at `m+2` adds one FRI layer. The constraint degree bound (3, or 4 at
`h ≤ N/4`) limits the honest prover, not soundness.

**The prover's guards:** R1, the rank check (under zero knowledge
below); R2, the claimed sums blinded, one blinding QM31 a component on
one row through `BlindRelation`; R3, the FRI mask's rank: `R`'s 8 columns
take independent affine coefficients, which span M31^4 except with
probability about 2^-155, so it holds by construction with no check; R4,
hedged randomness: each attempt's stream is seeded with
`BLAKE2b-256("vos/mask/seed/v1" ‖ 32 OS bytes ‖ witness digest ‖
attempt)`, so a witness proved again from a replayed OS state never
reuses a mask. The witness digest is `BLAKE2b-256("vos/mask/witness/v1"
‖ statement ‖ each main column's hash)`: the statement as u64
little-endian words (the header's word count, then the header the
transcript mixes: the format's number, its configuration and each log
size; then the DEEP batching, the interaction PoW, the channel's tag and
the masking's salt columns, FRI mask columns and log mask rows), the
public values' count as u64 and each value's 4 limbs as u32, all
little-endian; then each main column's `BLAKE2b-256` over its values, 4
bytes little-endian each, in commitment order. Every private value of
the witness is in the main columns (`recair/src/masked/rng.rs`).

Its count is the security tool's under (c):

- **What (c) moves:** FRI tests `k = 4N` at 39's blowup 32, the DEEP
  term takes `k = 2N`, `d = 3` and a factor 2 for `π(z)`, and every other
  formula stays. The salts enter no term (Blake2b-256's collision resistance, which the tool does
  not model, binds them as it binds every tree).
- **146 / 82.70** at 24 queries, PoW 26, the query term binding at
  `m = 5`; 23 queries is the least that clears 80 (80.84). The DEEP term
  is 97.68, ALI 108.38, logup 111.60: the interaction PoW does not bind.
- **Derived, not cited:** the DEEP term's three (c) inputs (`k = 2N`,
  `d = 3`, the factor `2^j`), against Theorem 8 of eprint 2022/1216 with
  the AIR at level `m+1`, the composition at `π(z)` and lifted columns of
  mixed degree. About 15 bits of slack: a factor of 2^10 would not move
  the count.
- **The lifted protocol:** the tool counts the lifted batch as one
  Reed–Solomon code of dimension `4N`, each masked column's `2N` bound
  enforced by one more doubling of its lift; no paper in the fork's canon
  analyses the lifted variant.
- **The integer multiplicity:** counts are taken at the best integer
  `m ≥ 3`, as soundcalc takes them, so a small parameter move jumps the
  count (23 queries 80.84, 24 82.70).
- **The reference shape** counts R2's blinding (12 main and 8 interaction
  columns, 2 constraints, a fraction a row a component) and the FRI mask's
  8 columns as designed, and the batch exactly: 538 values, one a sampled
  column and a periodicity value more for each of the 28 columns sampled
  twice (the composition and the FRI mask once each, the salts never). It
  is the shape a test derives from the built masked components, field for
  field. The blinding's own
  soundness (a pole argument in the challenges) is counted only as logup
  fractions.
- **The masked verifier's shape** comes from its own layout (`k = 4N`
  whole, `j = 1`), never from the helpers that subtract Stwo's
  composition split (DIVERGENCE-004), which would put FRI's dimension at
  `2N` (`log_degree_bound` `m+1`) and overstate the batching term by about
  1 bit.

**The lifted tree binds no column to its own size.** The fork's lifted
Merkle verifier hashes one flat row a query, and FRI tests only the global
degree bound, so a column sampled at one point may be any polynomial below
that bound: a small chip may run as a longer cyclic trace. The only
per-column size binding is the periodicity value the DEEP batch adds for a
column sampled at two points. That is enough, by our own derivation,
reviewed by no one: every next-row read and every logup running sum is a
two-sample column, hence periodic at its chip's size, so each row's
fraction is periodic and any one period is a valid trace with the same
claimed sum; the same holds under masking (the columns at level `n + 1`,
the AIR at `m + 1`). It needs every committed column at no more than two
sample points, since a third would get no periodicity value; tests hold
the segment chip set, the device set, the recursion AIR and the masked
wrap to that (`every_*_column_is_sampled_at_one_or_two_points`,
`the_sample_points_match_pin_b`). The argument belongs with the lifted
count above in the cryptographer's review.

**Zero knowledge** is the argument's: honest-verifier zero knowledge of
the masked IOP, so zero knowledge in the programmable random-oracle model,
conditional on the rank check (R1: for every column class, the
randomizer's revealed functionals have full row rank over M31), which the
prover checks on every transcript and retries on with fresh masks (at
most 8 attempts; whether a transcript passes is a function of public
coins, so a retry leaks nothing), and on the FRI
mask `R`'s DEEP coefficients being of rank 4 (all but about 2^-155 of
draws, its 8 columns): `R` is witness-independent, so a simulator draws it
as the prover does, and the real and simulated batches differ by an
`R`-quotient, so FRI's transcript, its unsalted layer trees included, has
one distribution; no check runs for it. The masking's
gates (`vos-pvm-recair`'s `masked_gates`, `leakage` and the masked wrap's
tests; at a medium N under `heavy-gates` in `just test-proof`, at full N
in `just slice-gate`) are a regression
guard, not evidence of it: the soundness gates (acceptance at every size
on both channels, a broken constraint on the first, last and wrap rows
refused forced, the lifted preprocessed columns, the blinding unable to
cancel an unbalanced relation, malformed proofs refused without a panic)
and the statistical leakage gates (per field a χ² on 16 buckets, 4 at 64
proofs or fewer, and a pooled two-sample KS between witnesses;
uniformity, exact at 64 or fewer; α = 10^-3 over the family with
Bonferroni) find gross leaks only: at 2,000 small-circuit proofs a witness
a field leaking about 0.13 in total variation; at the real wrap's 32, by
uniformity, a field leaking about 0.6, and between witnesses only a field
fixed by the witness.

## What leaves the prover role

Only a statement and its masked final proof leave the space's prover role
(`docs/design/proving.md` A.5): segment, leaf and fold proofs, the served
rows, the witness, step counts, memory roots and registers past φ9..φ12
stay with the agent's replicas. The carrier audit checks it on a run
(`just test-carriers`, `vos_checker::carriers`): three nodes prove a read's
statement with the masked prover beside a fourth that replicates nothing
of it, every debug output's environment set, and every carrier's bytes
are searched for the run's own internals, above the floor below: in their
bytes, hex, `Debug` lists, M31 limbs, decimal digits and either byte
order, a store by its rows, each capture path shown to capture by a
canary. The internals are `proving.md` A.5's needles, the masked wrap's
randomness among them (`Kind::WrapRandomness`: each attempt's entropy and
seed, the witness digest, the blinding values, the seeds of the mask, salt
and `R` columns, shown by the prover's watch seam, a dev edge only). `just e2e-chain`
runs it over a whole run on chain: the Kreivo mock's extrinsics, every
work package sent to the JAM statements service on a PolkaJam testnet
with its extrinsics and work report, both venues' anchor chains and the
testnet's own logs and database.

**The search's floor.** A needle too small to tell from chance is not
searched (`node/checker/src/carriers/needles.rs`):
- a byte needle needs at least 8 bytes, 4 of them distinct;
- a number's forms need 4 distinct bytes, so most values below about
  2^16 are searched by their digits and `0x` hex alone, each matched
  whole;
- a single register below 2^24 is not a needle, nor a step count of at
  most 255 or a power of two, nor an M31 word of a device secret below
  2^20;
- a row's value below 2^24 is not a number's needle in a run of any
  values; the run over small values (every row's value in
  [2^20, 2^24)) searches each from 2^20 by its digits and `0x` hex,
  matched whole: below 2^20 a value's digits are a log's ports, sizes,
  counts and process ids by chance, and below 2^24 its bytes, three and
  zeros, a binary carrier's fields.

Every served row's key, value and salt and every value the run wrote,
served or not, are needles; so are each served value's plain and
domain-prefixed hashes, and the served rows and the witness blobs are
searched whole. The audit runs twice: over high-entropy rows past 2^40,
and over small values (`node/host/tests/carriers/audit.rs`).

| carrier | what it carries | reach | checked by |
|---|---|---|---|
| a submission: the venue's `submit`, Kreivo's `Submit` call, JAM's `Submit` item and its extrinsic | the statement (format, program id, space, public arguments, output, roots) and the format-39 proof | leaves | the audit |
| an anchor: Kreivo's `Anchor` call, JAM's `Anchor` item | space, window, kind, `S_w`, signer, signature | leaves | the audit |
| a JAM work package as it went, its extrinsics, and the work report a guarantor made of it | the items (registrations, anchors, statements) and their proofs; the verdicts, a function of the items | leaves | the audit, every form, on every package a node's or the run's client sent to a PolkaJam testnet, anchors and replays among them, each watched before it went, whether the node's answer came or not, and its report (`just e2e-chain`, the dev tooling's `vos_jam_dev::live::Watch`) |
| a signed Kreivo extrinsic: its envelope | the signer's nonce and the call | leaves | the audit, every form, on the mock's (`just e2e-chain`) |
| a chain's own record of what it was sent: its nodes' logs and database | blocks, guarantees, the packages and their extrinsics, the services' code | leaves | the audit (`just e2e-chain`, `Reach::Recorded`): every needle's bytes, whole hex and `Debug` list, a register file's bytes; not a number's digits, hex or bytes, a hash's hex prefix or a debug output's text, which the chain's own counters, gas, hashes and program bytes hold by chance. What it was sent is searched in every form as the packages and reports above; a statement's encoding and a work report are shown to be in its database as bytes, a report's hash in its log |
| a client's answer | the method's outcome: a read's output | leaves | the audit |
| the JAM statements service's storage, read over RPC at the finalized block | the spaces, anchors, evidence, `Seen` entries and items' outcomes: what the items carried, and the verdicts | leaves | the audit, every form (`just e2e-chain`), but the venue's layout constants and the space's clock, public in this carrier alone (`Audit::carrier_except`) and needles in every other |
| a live run's fault text: `ExitReason`'s `Debug` in `Fault::Agent` (a page fault's address among it; `node/host/src/pvm.rs:177-180, 218`), an executor panic's message (`node/host/src/executor.rs:67-68`, `node/host/src/fault.rs:58-61`) | text of the agent's own run, data-dependent | leaves: the applying node logs it at warn (`node/host/src/group/apply.rs:232-236`), and a query returns it to its caller as `CallError::Failed` (`node/host/src/queries.rs:331`) | not audited: the audit runs happy paths. The replica's logs and an authorized caller hold the agent's state already, so this is not the prover role leaking, but its content is not bounded; the fix (the variant alone, a static panic message with its place) and one audited run of a faulting kernel are not made |
| a panic while a proof is made; a failed proof's error | the panic's place (file and line), not its message; `StatementError::Failed`, which names what failed and no value | leaves (standard error, the logs) | the redacting hook (`node/prover/src/redact.rs`) while a proof is in flight; the audit over the logs |
| logs, at every level | ids, windows, codes, the prover's backlog counts, each proof's time in seconds, and Stwo's `info!` of a proof's size estimate; at debug level, an agent's guest log lines (`refine_host`'s `log`), text the agent's own code writes, which carries whatever that code puts in it | leaves | the audit, for the node's own lines; an agent's are its author's, audited with its code; the time and the size estimate are side channels as below |
| standard error | the node's log: `vos` writes its tracing there, at `VOS_LOG`'s level (info by default); no debug output in a production build | leaves | the audit (the run captures both) |
| the debug outputs: the PVM's instruction trace, `VOS_PVM_DEBUG`'s registers and native code, `CPU_DUMP`, `CPU_EXPR_DUMP`, `VOS_PROOF_PROFILE` | a run's steps, pcs, registers and trace rows | only a `debug-internals` build (`vos-pvm`'s, this crate's) | `just check-no-debug-internals`: no production edge enables it, and the node's binary names none of them |
| the operator's `/stats` | stage histograms, `refine_gas` and `step_gas` among them: a kernel's gas, so its steps, within a quarter and in sums | the node's operator | not audited: the operator runs the replica |
| the tests' `target/tmp/wrap/` | final wraps (39), their formats, words and judgements' inputs | the test machine | `vos-pvm-recair`'s `recursion` `wrap_files`: each verifies as a final wrap, and nothing else is there |
| the agent's log, snapshots and peer frames | `Resume` with the served rows; work results with each `Attest` (witness, output, public arguments, roots); `Proven` with the proof's hash | the agent's replicas | the audit: no node proof, memory root or register file |
| frames to a node of the space that does not replicate the agent, and that node's disk and store | heartbeats, placements, forwarded requests | leaves | the audit, every needle |
| the node's blobs and disk | final proofs, large work results, the store | the node | the audit: as above |
| the agent's records of its attests at a cut (`keys::attested`, node-local rows every replica's apply writes alike) | each attest whole (witness, output, public arguments, roots) until its window's roots age past `MaxRootAge` | the agent's replicas, and the snapshots they send | the audit: as above |
| the prover's table | each job's record (`witness_input` among it) until it finishes, its statement, its proof's hash; an unfinished job is dead once its roots age past `MaxRootAge`, and a job of an agent the node no longer replicates goes (`node/prover/src/worker.rs`'s `prune`) | the prover's node | the audit: as above |
| an agent on JAM: its work packages and results (`vos-jam`) | its batch, its rows' witness and its attests whole, served rows included | JAM's validators and DA | by design: an agent on JAM keeps no row from JAM, so a statement of one hides nothing from it |

A proof's time and Stwo's size estimate in the logs,
and the operator's gas stages, reveal the trace's size, as the prover's
time does (the side channel below); a statement is published at the
window's cadence for it.

## The external audit

Required before value rides on a proof. [AUDIT.md](AUDIT.md) maps its
scope to files and functions. Its scope:

- the base segment AIR, above all the parts listed above as not yet under
  a forgery gate;
- the fork's divergences: the Blake2b channel, fold step 3, affine DEEP
  batching, the completeness backport;
- the security tool's counts (`src/security.rs`), variant (c)'s among
  them. The tool takes soundcalc's convention, the least term binds; a
  union bound over the terms puts format 39 at about 81.2 bits, still
  above 80, but it would not hold at 23 queries, so the 24-query pin is
  the robust one;
- the recursion AIR: the in-AIR verifier, the gate compiler (constraint ≡
  gate), the claimed-sum handling, the `Gate` relation's signed
  multiplicities, the fold;
- the leaf's binding (its entry constants, the io-hash's range checks),
  the wrap, `vos-pvm-final-verifier` and `vos-statement`;
- `derive` (layout to preprocessed columns, its refusals) and the program
  id's derivation;
- the masking: the masked transcript's order, R1 to R4, the blinding's
  soundness, and the zero-knowledge argument's premises; later, the public
  sums' re-cut;
- the device path: `vos-pvm-device`'s pre-check, decode and verify; the
  device chip set (the word ledger's three chips, DeviceBoundaryChip,
  DeviceIoChip and the data table); the CPU cut and the pin code that
  computes a program's chips and cut from its code; a device program's id;
  the stock kernels.

Who performs it, and when, is open.

## What a verified proof does not guarantee

- **Program intent:** a proof shows the bytecode ran as the PVM runs it,
  not that the bytecode does what its users think. Auditing it is the
  deployer's, or for a kernel, the governance that pins its id.
- **The boundary's meaning:** a segment proof binds its boundary states;
  whether they are the ones the deployer meant is for the deployer to
  check, against values published out of band.
- **Liveness:** a prover may refuse to prove; a missing proof is not a
  refused one.
- **Side channels:** the prover is not constant-time, and its time reveals
  the trace's size. Statements are published at the window cadence for
  that reason.
- **Cost:** no gas is proved.

## Deployment checklist

- [ ] **Pin each kernel's program id** by governance, recomputed from the
  kernel and its install record by someone other than its prover; pin the
  final verifier's build (its wrap root is a constant of it).
- [ ] **Audit each kernel** whose id you pin: its roots, its nonces, its
  salted fields, and that it never takes a short witness read for the end
  of its input (a proved read returns at most the capacity, not the live
  `min(capacity, remaining)`).
- [ ] **Cap the submission's length** before decoding it; key accepted
  statements on the statement id.
- [ ] **Publish a segment's expected shape and boundary** where a segment
  proof is verified directly (a reference path; no production build
  verifies one natively).
- [ ] **Plan for liveness failures:** a fallback or another prover.
- [ ] **Treat `javm` as the reference:** a proof shows a trace matches
  javm's PVM semantics, so a javm bug is a bug here.

## Reporting issues

Soundness or verifier-DoS bugs: a private issue, or the maintainers
directly. Interpreter divergences belong in the javm tracker.

## Stability

- Stwo and javm are pinned to git revisions in the workspace's
  `Cargo.toml`; a deployer who vendors this crate pins them too.
- A proof's encoding is specified by its source and its format number
  alone; keep a verifier build beside any archived proof.
