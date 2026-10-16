# Review: `proving.md` draft 1 ("Proving: layers, formats and verifiers")

Reviewer: Fable, 2026-10-16. Read-only. Inputs: the draft; `research/slice-5/`
(audit, spikes 1–4b, masking review, mobile, kreivo-pallet, critique); plan
draft 6; identity §5/§11/§12; core-model §11–12; `pvm/proof` on vos-core
(`proof.rs`, `verifier/src/lib.rs`); the monorepo at `916aefb5`
(`circuit_multiverifier/src/verify.rs`, `circuit_params`, `stark_verifier`).

## Verdict: **right architecture, not yet implementer-ready. Draft 2 required.**

The layering (base proofs → generated leaf circuits → one 2-to-1 fold shape →
a masked wrap → one statement format for every venue) is the right design, and
every number I checked against the research is reproduced correctly (the few
drifts are listed under R12). What is missing is precision where soundness
lives: §3 names *what* is bound but not *how*, in five places an implementer
cannot fill in alone; two design choices the targets of §4 depend on are left
implicit (whether device proofs enter the fold; whether the Poseidon2 gate is
in scope); and the single-segment device shape (§8) is a sketch, not a
binding argument. None of this is a redesign. The owner's three concerns —
feasibility retired early, mobile not lost, Kreivo first — are each served
only partially by the milestone order (§7 below).

---

## Required changes for draft 2

**R1. Define the anchor and its check (§3.2–3.3).** The draft says "the
anchor is carried from the leftmost leaf" and lists "the public data root" in
the program id, but never says what the anchor *is* in a chain-path segment
(today: `proofs[0].initial_state.memory_root`, a page-Merkle root over code,
data, zeroed stack/heap **and the private arguments and witness pages**,
`verifier/src/lib.rs:786-806`) nor how any circuit relates it to the program
id. Draft 2 must state: (a) the page layout that separates public pages from
private pages into disjoint subtrees (or the recomputation rule); (b) which
node checks `public_part(anchor) == program_id.data_root` (leaf or wrap);
(c) that the private part is dropped there and reaches no public input; (d)
that, because no root ever leaves the prover role, **the salt page is not
needed** (closing plan 5.1's open question explicitly, with the carrier
audit R7 as the guard). Spike 3 §4 item 2 already calls this "the real design
work"; the draft inherits the gap.

**R2. Bind the ends of the chain, not only its joints (§3.3).** Continuity,
adjacency and io-hash carry do not stop a prover from folding a *prefix* of a
run, or a run that starts mid-way. Add to the fold's statement: the leftmost
leaf's initial state is the kernel's entry state (pc = entry, ts = 0, the
loader's register image with φ7/φ8 as witness, memory root = anchor); the
rightmost leaf's final state has pc = halt (the io-hash in φ9..12 is only
meaningful at halt). The same two checks apply to a device proof as a
single-segment statement. `verify_chain_standalone` today checks neither.

**R3. Specify the fold node's output and the padding rule (§3.3).** A leaf
emits "the segment's position"; a fold must carry a *range* `(first, last)`
and check `left.last + 1 == right.first`. Say what the fold compares for
continuity (full state or a Blake2s digest of it: 13 registers, pc, ts, root)
and how a fold learns "the leaf-circuit set for that id": the program id's
preimage must be a fold witness and the id recomputed in-circuit, or the set
hash carried beside the id. Then either define padding nodes (an empty child
flag, how it is refused as a gap in positions) or drop "padded to a depth
class": with every node padded to one shape, the root proof is
depth-independent and the segment count is private; only timing leaks. I
recommend dropping the depth class and bounding timing by publishing at the
window cadence (identity §11's rule for anchors).

**R4. Specify the statement digest end to end (§3.5).** Define, with a
canonical encoding and domain separation, (i) `io_hash = H(public_args ‖
output ‖ roots)` as the kernel computes it in φ9..12 (today's `compute_io_hash`
takes `(public, return)` only — roots must be added to the derive prologue);
(ii) `digest = H("vos/statement/v1" ‖ format ‖ program ‖ space ‖ io_hash)` as
the wrap's single public input; (iii) which fields the proof binds (program,
io_hash) and which the venue authenticates (format accepted, roots anchored,
`space` consistent with every `RootRead.space`; a rootless statement has no
space binding and must say so). Kreivo's `id` in `kreivo-pallet.md` §2 step 6
and this digest must be one function with golden vectors. Add the rule for
kernels: a legitimate repeat (two identical payments) collides under
replay-by-id, so such kernels carry a nonce in `public_args`.

**R5. Decide whether device proofs enter the fold, and if so what that
costs (§3.1, §4, §5, §10).** The diagram feeds masked device proofs into leaf
circuits. That requires an in-circuit verifier of a *masked* (c) proof —
salted leaves, composition committed whole at `4N`, lifting at `m+2`,
composition sampled at `π(z)`, the FRI mask column, blinded claimed sums and
the public-sum re-cut — none of which StarkWare's `stark_verifier` has. It is
a second soundness-critical extension of their verifier, absent from §3.1's
AIR-change list, §10's risks and every milestone. It also makes a rate-1/2
device proof (60 proven bits, no slack beyond a conjecture the critique
notes is refuted as stated) the weakest link of a chain-bound final proof,
which §4 glosses with "the same floor". Recommendation: **v1 device proofs
are verified natively at the space's ingress and recorded as facts; chain-
bound statements are node-proved over space state** (mobile.md §6 already
assumes a node re-proves). Keep "device proofs as leaves" as a named later
option with its own gate. Either way, draft 2 must say which, and §4's
device row must say where those proofs may go.

**R6. Make the Poseidon2 gate's status consistent (§3.3, §3.4, §4, §9, §12).**
§3.3 calls it "an optimization"; decision 2 says ≥80 proven bits *needs* the
small wrap, which needs the gate; §9 places it "M2 or later"; §11 funds it
nowhere. Also state the precondition precisely: the small wrap needs the
*root fold* on a Poseidon2-M31 channel and a wrap circuit with **no Blake2s
gate**, because the 10-bit XOR table alone makes every Blake-bearing circuit
2^20 rows. Then the parameter rows must agree: §4's small wrap is 18 queries,
§3.4's gas (54–76M) is the 13-query measurement; at 18 queries expect ≈65–70M
unmasked, ≈90–100M masked by spike 4a's model. Put the gate in a milestone or
change the target.

**R7. Pin the fold shape as a format constant with headroom (§3.3).** The
monorepo pads every node to the elementwise max over all leaves *and* the
multiverifier (`circuit_params/src/lib.rs:190-215`, a fixpoint). If the shared
shape is "the max over kernels", a new kernel with a larger leaf changes every
leaf circuit's hash, hence every program id, hence every Kreivo registration.
State: the fold shape is a format constant chosen with headroom; a kernel
whose leaf exceeds it is refused (or gets a new format). Add the headroom
number to M1's gate.

**R8. Fix §4's basis and say what the proven floor buys (§4).** (a) The
formula "PoW + queries × log blowup" is the ethSTARK up-to-capacity
conjecture, which the critique records as refuted as stated (Diamond–Gruen,
Crites–Stewart) with a salvaged fixed-rate form costing +3–15% queries. Name
the conjecture used and the salvage margin, or raise the query counts. (b) 60
proven bits is ≈2^60 hash evaluations: inside a well-funded forger's reach
today. Say plainly that value at stake rides on the conjectured figure until
the wrap reaches 80, and that the stock wrap (62 proven) does not. (c) "Grover
halves both" is a heuristic the critique tagged [memory]; mark it so. (d)
Define "proven" operationally: the Johnson-bound count including the DEEP/ALI
and logup error terms, produced by one tool per shape and pinned in the format
tests, so the two numbers the verifier checks have one source.

**R9. Make §8 a binding argument, not a sketch.** For the no-boundary shape
specify: how a first-touch (`ts = 0`) ledger value is constrained by address
region — preprocessed data table for the data region, zero for stack/heap,
free witness only in the argument window at φ7/φ8 — and that an access
outside every mapped region is refused (the live PVM traps; the proof must
not accept what the run would not). State that read-only pages still refuse
writes without MEMORY_PAGE's permission bits. Say that the device shape's
"public data root" is the table's presence in the preprocessed root, a
different object from the chain path's page-Merkle data root, and that both
are admitted by the program-id rule. Note the masked 2^11 per-component floor
(h ≤ N/4 at 80 queries) and its +0.07 s.

**R10. Add an early feasibility checkpoint inside M1 and an early phone run
(§10–§11).** M1 is 8–12 weeks with its sharpest risk — the window kernel's
leaf at ≈2^22 rows, ≈21 GiB at blowup 4 by spike 4b's doubling rule, against
a 24 GiB gate — retired only when the whole vertical path exists. Order M1
as: (1) AIR conformance + leaf for one kernel, measured (gate: fold ≤ 3×
segment time, ≤ 24 GiB, and the fallback named: narrow BLAKE2b or blowup 2
for the leaf proof); (2) fold node; (3) wrap + `vos-final-verifier`. And the
mobile claim rests on an unmeasured ARM factor: the auth statement already
cross-builds and proves byte-identically under qemu; a one-day run of the
as-built and floor-proxy shapes on one real phone belongs in M0, not M4.

**R11. Specify roots versus anchors (§7).** The kernel verifies rows against
a *committed-map* root (spike 3: "not a space-level root"); the pallet
compares `RootRead.root` to the anchored *space-level* root
(`kreivo-pallet.md` §2 step 5). Draft 2 must choose: the kernel's witness
carries the full path row → map → agent → space and `RootRead.root` is the
space root, or the anchor covers a vector of agent roots. State the latency
this implies (a statement waits for the window's anchor) and that the signed
venue-migration point must be recorded on both venues so each refuses
windows outside its range.

**R12. Reconcile numbers and tags.** §2: "100M gas [model]" for the 2^20
blowup-8 layer is measured (99.5M, spike 4a) and its memory is 12.8 GiB
(4a) / 11.3 GiB (4b) — pick one and cite. §3.4: the stock wrap masked is
≈224 KB, not "140–160 KB". §11: M0+M1 (11–17 weeks) should be reconciled
with spike 4b §8 (10–13 to a working tree, 18–26 to production) line by
line, or the lower bound is not credible. §4 row 1: say "blowup 4" means the
factor (log 2), since vos names the same setting MOBILE's `log_blowup 2`.

**R13. Add the implementer's appendix.** Draft 2 is "implementer-ready" only
with: the leaf statement's `claims_to_mix` order (= vos's transcript prefix,
word for word, with the interaction PoW position); the relation-id scheme and
the list of 9 next-row-mask chips and 14 unpaired chips; the fold node's
output layout; the format-version registry (Blake2s-M31 segments, device
masked, fold, wrap — new numbers, not 24/25); the final-proof channel (Merkle
Blake2b-256 is stated; the Fiat–Shamir hash is not); the exact contents of
`Attest` and of every struct that may leave the prover role; the golden
fixture list; and a per-node memory/time budget table.

---

## Recommended changes

- **Device masking at rate 1/2.** Keep 80 queries (100 conjectured) but add
  the critique's framing: acceptable for an authorization a space re-checks,
  never for settlement. If R5 keeps device proofs off-chain this is a
  one-line note; if not, it is a target change.
- **Low-entropy public fields.** Add a kernel rule: anything in `output` or
  `public_args` derived from private data is a nullifier or salted
  commitment, never a plain hash of a guessable value (Fable §3 of the
  masking review).
- **Timing.** Replace "proving time leaks" with the mitigation: final proofs
  are published at the window cadence.
- **Interaction PoW** also for the fold layer's proofs (the fold circuits have
  logup too); say so.
- **The leaf's preprocessed root.** State whether the segment's preprocessed
  root is a constant of the leaf circuit (so the leaf circuit hash pins the
  kernel's code) or an output the fold checks; the former is simpler.
- **Kreivo P0** (registries, anchors, `RejectVerifier`, `Record`) has no
  dependency on the recursion: start it in slice 5 with the owner's team, so
  the pallet's governance and anchor model mature while M1 runs.
- **Mobile decision 3** is framed to favour the general profile, but its
  0.36–0.9 s rests on four unbuilt levers and an unmeasured ARM factor, and
  misses sub-second on Tensor (0.65–1.6 s). Present the dedicated Poseidon2
  credential AIR (3–6 weeks, tens of ms, PQ-consistent) as the fast path for
  authentication and payment authorization, with the device profile as the
  general path; let the owner fund one or both. Name the protocol cost of the
  Poseidon2 root kind honestly (vos-tree hasher change, JAM witnessed reads).
- **Merkle-path precompile (§8 lever 3)** is a new soundness-critical chip
  encoding vos-tree's six path rules, not a hash accelerator; give it its own
  effort line (≈3–5 weeks, like narrow BLAKE2b) or M4's 6–10 weeks is short.
- **§6 Kreivo**: carry over the modesto check order (size cap, strict decode,
  panic guards, program from the proof, STARK, io-hash last) as normative;
  the draft has "cheapest first" only.
- **External audit scope**: add the generated-gate compiler (constraint →
  gate equivalence) and the public-sum re-cut to the audit list.

## Owner decisions to add or reframe

1. **Do device proofs ever enter the fold?** (R5.) Recommend no in v1.
2. **The Poseidon2 gate: slice 5, 6, or never?** It decides decision 2
   (≥80 proven), the 4× fold cost, and the small wrap. Not optional as framed.
3. **Proven-bits floor at value.** Is a chain-bound statement acceptable at 62
   proven bits (stock wrap) during slice 6, or does value wait for 80?
4. **Maps phones read: Poseidon2 root kind (protocol change) or the vos-tree
   path chip?** Currently buried in §8 lever 3.
5. **Decision 3 reframed** as "fund the dedicated credential AIR, the device
   profile, or both" with the Tensor miss stated.
6. **Anchoring latency**: statements wait for the window's anchor (R11);
   confirm the window length Kreivo will run.
7. **Who builds Kreivo P0 and when** (parallel to slice 5 is possible).
8. Decisions 1, 4, 5 and the "decided on the evidence" list are sound as
   framed.

---

## Draft 2 check (2026-10-16)

Each R1–R13 re-checked against draft 2. Verdict: **R1–R13 are addressed; four
small fixes are needed before the owner's decisions, all local to §3.3, A.1,
A.3 and §10/§3.1.** Nothing newly introduced is wrong in direction.

| R | status | note |
|---|---|---|
| R1 anchor | addressed (decision 7) | witness-input precompile makes the image root a program-id constant; salt page dropped with its reason. See fix D4 below for the precompile's own AIR binding. |
| R2 ends | addressed | entry/halt flags, root carries `first = 0`; fixtures A.6 cover prefix and mid-way. |
| R3 fold output, padding | addressed | ranges, state digests, program-id preimage as witness, depth class dropped. See D1 (fold circuit self-hash) and D3 (output width). |
| R4 digest | addressed | io-hash gains roots; digest defined with domain separation; who-binds-what, nonce rule, low-entropy rule all present. |
| R5 device proofs | addressed (decision 2) | out of the fold in v1, with the cost of the later option named. |
| R6 Poseidon2 gate | addressed (decision 3) | preconditions and 18-query numbers consistent (≈65–70M / ≈90–100M). |
| R7 fold shape constant | addressed | but see D2: "≥ 2× headroom in rows" doubles every node's prover memory. |
| R8 §4 basis | addressed | conjecture named with the salvage margin (39 and 84 queries are +5%, the low end of 3–15%); tool-pinned counts; Grover marked heuristic; the 60-bit statement made. Table arithmetic checks. |
| R9 §8 binding | addressed | first touch by region, unmapped refused, permission table, device vs chain data root. Implementation of the region check is left to M4; acceptable for a design. |
| R10 early checkpoints | addressed | M1 ordered with the leaf first and the fallback named; phone run in M0. |
| R11 roots vs anchors | addressed | full path to the space root; latency; migration point on both venues. |
| R12 numbers | addressed | 99.5M measured; 11.3 GiB; 200–224 KB; M0+M1 reconciled with spike 4b. |
| R13 appendix | addressed | A.2's chip lists verified against `pvm/proof/src/chips` (14 `finalize_logup()` callers, as listed). See D1 and D3 for A.1/A.3. |

**Fixes required before the owner's decisions:**

- **D1. The fold circuit cannot hold its own hash as a constant (§3.3).** "Each
  child's circuit hash is a leaf circuit of the program id, or the fold
  circuit" is circular: a circuit's hash depends on its preprocessed columns,
  constants included. Use the standard self-carry: the fold takes the fold
  circuit hash as a witness word, checks each child's circuit hash against
  the leaf set or that word, and copies the word into its output (A.3's
  trailing "circuit hash (8)" is the right slot); the wrap, a different
  circuit, pins the true fold hash as a constant and checks the root's word.
  State this in §3.3.
- **D2. Headroom in rows contradicts the memory gate (§3.3, §10, A.7).** The
  leaf is ≈2^22 rows and ≈21 GiB at blowup 4; "≥ 2× headroom in rows" makes
  the shared shape 2^23 and every node ≈42 GiB. Give headroom in component
  columns and in rows of the small components, not in the tallest
  component's height, or lower the gate's row target and say what a kernel
  that exceeds it does today (the window kernel itself must fit).
- **D3. The node output is an 8-word digest, not 44 words (A.3).** StarkWare's
  multiverifier reserves `N_RESERVED = 8` output words (one Blake2s digest),
  and a child's output enters its statement as that digest. A.3 must say:
  the 44 words are the preimage of the node's output digest; a fold takes a
  child's preimage as witness, hashes it in-circuit (≈3 compressions) to the
  child's committed digest, then runs its checks on the words. Likewise the
  program-id recomputation is an in-circuit hash: name the hash (Blake2s, so
  the fold and Kreivo compute the same function) in §3.5.
- **D4. A.1's claim list is wrong, and the precompile has no AIR binding.**
  (a) `claims_to_mix` is mixed before the trace root; the main and interaction
  commitments, the interaction PoW nonce, the logup challenges (derived, never
  mixed) and the claimed sums are not claims. A.1 should list only items 1–5
  (domain words, the configuration words `stark_verifier` does not already
  mix, component set and log sizes, preprocessed root, boundary states) and
  state that vos's segment prover adopts the circuit verifier's transcript
  order for everything after, as spike 4b §2.2 did for COMPARE. (b) The
  witness-input precompile is a host call that writes prover-chosen bytes
  into memory: §3.1/A.2 must say how the AIR admits it (dispatch committed in
  PROGRAM_MEMORY like `0x400`, writes bounded to the range the call names, a
  size cap, no other effect) and that `derive` admits the new id; add the
  live≡traced test for it to M0's gates.

**Recommended, not blocking:** the Blake2b Fiat–Shamir channel (decision 6)
is new code in the fork (vos has Blake2s and Poseidon2 channels only); note
the day of work. The R10 fallback "leaf proof at blowup 2" roughly doubles
the fold's cost (≈78 queries); say so beside it.
