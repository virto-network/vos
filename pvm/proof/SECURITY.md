# vos-pvm-proof: security considerations

What a verified proof proves about a PVM execution, what it does not, and
which inputs a deployer must supply honestly. It is descriptive, not a
formal argument. The design is `docs/design/proving.md` (§3.6 the
statement, §4 the security levels, §6 the verifiers) and
`docs/design/recursion-air.md`; [`docs/status.md`](./docs/status.md)
lists what the AIR binds per opcode.

There are two verifying paths:

- **A segment proof,** verified by `vos-pvm-proof-verifier`
  (`verify_standalone`, `verify_kernel_segment`, the chain verifiers):
  formats 35 and 36. Peers and tests use it; so do the refine bundles.
- **A statement,** a kernel's whole run: its segments (35) verified in
  leaves, folded (32), the root wrapped (28), the wrap verified by
  `vos-final-verifier` and judged by `vos-statement`. This is what a venue
  (a chain's pallet, the JAM agent) accepts.

## Formats and their bit counts

Each number names one AIR, one channel and one set of parameters
(`src/format.rs`). Counts are conjectured / proven bits at the format's
reference shape, from the security tool (`src/security.rs`):

| format | proofs | channel | counts | floors | status |
|---|---|---|---|---|---|
| 35 | segments, hardened AIR | Poseidon2-M31 | 104 / 62.86 | 100 / 60 | admitted |
| 36 | segments, legacy encodings | Blake2s | 96 / 57 (at MOBILE) | 96 / — | admitted, legacy only |
| 32 | leaves and folds | Poseidon2-M31 | 108 / 63 | 100 / 60 | reserved: proved and verified inside the recursion, refused by every outside verifier |
| 28 | the final wrap, unmasked | Blake2b-256 | 146 / 82.6 | 100 / 80 | admitted |
| 37, 30 | device and credential proofs | Blake2s-M31 | 106 / 62 | 100 / 60 | reserved |

- **Conjectured** bits are PoW plus queries times log blowup (the ethSTARK
  conjecture, refuted as stated in 2025; the parameters carry a margin for
  its salvaged form). **Proven** bits are the Johnson-bound count with the
  DEEP, ALI and logup terms. The counts are the tool's own model, pinned by
  the format tests; no one outside has reviewed them.
- A verifier rejects a number the registry does not admit, a retired one
  (24 to 27, 29, 31, 33, 34) among them, and a proof on another channel
  than its format's. Under every format but 36 the proof's configuration
  must equal the format's, and its counts at its own shape must reach the
  floors.

**End to end, the proven bound is the weakest inner format's: 62.86 bits,
not the wrap's 82.6.** Forging a leaf's segment forges the statement. The
conjectured bound is 104. Under Grover's heuristic that is about 31 proven
and 52 conjectured bits against a quantum prover: post-quantum readiness
rests on the conjectured count.

**Format 36** is below the 60-bit proven floor (57 at its MOBILE shape;
the proof carries its own parameters, held only to 96 conjectured bits and
a `PcsPolicy`). The default prover entry points and the refine bundles
still produce it. It is admitted for that legacy path alone and has never
been published in a statement: a leaf verifies a Poseidon2-M31 segment
proof of the format its circuit holds as a constant, 35. Its
retirement, or the refine path's move to 35, is open.

## The segment AIR

- **Hardened in slice 5.** An audit of the AIR in four groups (G1 the CPU
  and the register ledger; G2 memory, page permissions, the root boundary
  and the host verifier; G3 arithmetic; G4 BLAKE2b) found holes that years
  of tamper tests had not. Each was fixed only after a forgery gate, a
  consistent forged trace, was written and accepted by the unfixed AIR; the
  gates stay as tests (`tests/*_gate.rs`). 25 chips, 5,177 constraints.
- **Not yet under a forgery gate of that kind:** PROGRAM_MEMORY's decode
  binding, JUMP_TABLE (one padding fix), the lookup tables, MEMORY_PAGE and
  MEMORY_MERKLE, the witness-input chip, the boundary-binding argument
  (formats v5/v6), the segment cut and closing-flag rule. These are in the
  external audit's scope (below).
- **Recorded, unfixed:** an invalid dynamic jump cannot be proved (no
  kernel needs it); the ledgers cannot prove a gap of 2^27 steps between
  two accesses to one key; a BLAKE2b pointer within 256 bytes of 2^32
  cannot be proved. Each makes an honest run unprovable, never a false one provable.
- **The Ristretto and scalar chips are removed:** they were unsound.
  Precompile ids 110 to 114 are served nowhere, and `derive` refuses a
  kernel that reaches one.
- **The witness input (`0x401`)** is a kernel's only argument channel:
  CpuChip binds the call's destination, capacity and count (at most the
  capacity, written to φ7), and WitnessInputChip writes each byte to the
  memory ledger at the call's timestamp, the addresses a carry chain that
  cannot wrap past 2^32. The register ledger orders reads before writes in
  a step, so a call cannot read its own result. What a kernel read is the
  `witness_input` of its attest.
- **The halt rule:** a halting step's `next_pc` is `PVM_HALT_ADDR`
  (2^32 − 2^16), which no code offset reaches, so a segment ends at that
  pc exactly when it ends at a halt. A trap keeps `next_pc = pc`: a panic
  cannot present as a halt. At the halt φ9..12 hold the io-hash.
- **No gas is proved.** A statement says nothing of a run's cost: the live
  host meters, and live ≡ traced holds for the runs the host completed.
  The prover role bears the cost of a run it chose to prove.
- **Page permissions are part of a program's identity.** A kernel's
  regions (read-only data and the argument window readable; read-write data,
  heap and stack writable; nothing else mapped) are preprocessed constants
  of MemoryPageChip, so they enter the preprocessed root: a store to a
  read-only page, or an access to an unmapped one, does not prove. Refine
  machine slices, whose pages change permission at run time, prove on a
  writable layout; refine's replay binds their permissions.
- **No chip-isolated proof verifies standalone:** a proof with
  `component_mask = 0` (the explicit-components test path) names no
  boundary chips, and `verify_standalone` refuses it before any
  cryptographic work, as it refuses a mask outside this AIR's chips or
  whose popcount is not the component count.

## Trust boundary: a segment proof

| input to `verify_standalone(proof, hash)` | trusted? | |
|---|---|---|
| `proof.format_version` | no | an admitted number, on its format's channel |
| `proof.interaction_pow` | no | checked against the format's bits before any relation challenge; 0 under format 36 |
| `proof.stark_proof` | no | verified by Stwo, after a hostile-input preflight of every nested length |
| `proof.claimed_sums` | no | must sum to zero; the boundary chips' must equal the sums recomputed from the boundary states |
| `proof.log_sizes` | no | capped by `DEFAULT_MAX_LOG_SIZE` (overridable) |
| `proof.initial_state`, `proof.final_state` | bound | registers, pc and ts bound to the committed boundary columns and to the trace; `memory_root` to the in-AIR page tree of the images; `memory_commitment` is unbound metadata |
| `proof.pcs_config` | no | the format's exactly, but under 36, where `PcsPolicy` sets the floor; Fiat–Shamir-bound |
| `hash`, the preprocessed root | **yes** | the class's program identity: its code, layout and permissions, at its shape. For a kernel, the install's record derives it, and the program id covers it |

The preflight, the format checks, the root against `hash`, the logup sum,
the boundary binding, then Stwo's verifier, in that order.

### Refine bundles (format 36 children)

`RefineProofBundle` is an ordered closure of single-program child proofs.
Its transcript binds the outer artifact hash, the invocation's arguments
and gas, every inner `(slot, generation, program-hash)`, each child's
format, shape and commitments, the sparse state and page commitments, the
host calls 9 to 14 with their registers and state hashes, and the exit.
Production artifacts use `encode_refine_proof_bundle` /
`decode_refine_proof_bundle`, which cap the bytes before parsing and charge
every declared vector against an allocation budget before reserving it.

`verify_refine_bundle_authenticated` needs a trusted mapping from each
machine identity, format, shape and `PcsConfig` to its preprocessed root,
so a proof of other code or parameters cannot be relabelled with a signed
program hash. It returns `ReplayRequired`: it does not bind the recorded
native state hashes or exits to the child statements, nor prove calls 9
to 14's state changes. Only `verify_refine_bundle_replayed`, which reruns
the committed program and regenerates each child's roots and boundary
states, is an end-to-end refine acceptance.

## Trust boundary: a statement

- **The wrap's verifier pins its own circuit.** `vos-final-verifier`
  holds the wrap's preprocessed root, its log sizes and format 28's
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
- **The rootless rule:** only a root binds a statement's space. A rootless
  statement must claim no space (`SpaceId::NONE`), or one proof would take
  a new id under every space. A kernel that does not state its roots in
  its io-hash (the window kernel, until the SDK does) leaves its handler
  to check what its output says it read.
- **Not yet bound to a venue.** A rootless statement is valid at every
  venue, forever; a rooted one is bound to a venue only by the rule that a
  space anchors on one venue at a time, which `judge` does not check. A
  venue domain, or migration refusing windows in code, is slice 6's
  design. Until a kernel states its roots, no venue should act on its
  statements beyond tests.
- **Every re-pin is a governance event.** A segment format bump (any
  hardening of the base AIR) changes every program id; a change to the
  recursion's compiler or gates changes every leaf circuit's hash, the fold
  circuit's hash and the wrap's pinned root.

## Panic-freedom

A FRAME runtime cannot catch a panic (no unwinding on wasm32 without std;
a panic aborts the block's import), so no guard can wrap the verifier. The
final verifier and `vos-statement` must be panic-free on every input by
construction: the shape and sample checks refuse before Stwo's indexing,
`unwrap`s and `zip_eq`s are reached, the statement's decode bounds every
count by the bytes left, and the fork returns an error where upstream
panicked on duplicate queries.
The evidence is three ten-minute fuzz campaigns (`fuzz/`) with an oracle;
a CI fuzz job, and an audit of every index and `unwrap` on the verify path
at the pin, are open.

## The Stwo fork's open divergences

The workspace pins olanod/stwo at `ab294189` (`vos/wrap`). Its divergence
log (`.claude/skills/paper-implementation-divergence-log.md`) holds two
open items the wrap's count rests on:

- **DIVERGENCE-011:** the first FRI round folds by `2^fold_step`, the
  circle fold in it. The security tool counts it so; a model counting the
  circle fold as its own round would differ by about 0.8 bits on format
  28's fold term.
- **DIVERGENCE-012:** affine DEEP batching, opt-in per format (28 alone),
  counted as `ε_lin(k)` by BCIKS20 Theorem 1.6. It carries the wrap from
  74.7 to 82.6 proven bits, and needs a cryptographer's review of the
  citation and the count: if it is wrong, the wrap is at 74.7, below its
  80-bit floor (the end-to-end bound, 62.86, is the inner formats' either
  way).

## Masking

None yet. Every proof is unmasked: the wrap's witness (digests,
positions, the io-hash, the fold word) and its trace are in the clear.
Segment, leaf and fold proofs must never leave the prover role. Masking
the wrap (with a new final format) is slice 6.

## The external audit

Required before value rides on a proof. Its scope:

- the base segment AIR, above all the parts listed above as not yet under
  a forgery gate;
- the fork's divergences: the Blake2b channel, fold step 3, affine DEEP
  batching, the completeness backport;
- the security tool's counts (`src/security.rs`);
- the recursion AIR: the in-AIR verifier, the gate compiler (constraint ≡
  gate), the claimed-sum handling, the `Gate` relation's signed
  multiplicities, the fold;
- the leaf's binding (its entry constants, the io-hash's range checks),
  the wrap, `vos-final-verifier` and `vos-statement`;
- `derive` (layout to preprocessed columns, its refusals) and the program
  id's derivation;
- later, the masking and the public sums' re-cut.

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
  salted fields.
- [ ] **Cap the submission's length** before decoding it; key accepted
  statements on the statement id.
- [ ] **Accept format 36 only on the legacy paths,** with a `PcsPolicy`;
  never as a statement.
- [ ] **Publish a segment's expected shape and boundary** where a segment
  proof is verified directly; set `max_log_size` to the honest shapes.
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
