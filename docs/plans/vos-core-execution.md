# VOS core execution model: refine, accumulate, agents, proofs

Status: DESIGN + PLAN (adversarially reviewed: 4 ground-truth readers + 3
independent design challengers over the actual code, 2026-07-08). This is
the leading track of the roadmap — VOS is the framework everything else is
written in, so this lands before (and in parallel worktrees alongside) the
showcase work in `federation-showcase.md`.

The vision under test: agents + sub-actors that also run in JAM. A main
**agent actor** (in JAM: a service) composes **stateless, refine-only
sub-actors** with cooperative multitasking; sub-actors running long tasks
with multiple `.await` points have suspension/resume managed by the parent,
which periodically **commits (accumulate)** its own and its sub-actors'
state; proving is **explicit** (`#[provable]` on concrete computations),
not re-prove-everything.

Sizing legend: **S** ≤ 1 day · **M** 2–4 days · **L** 1–2 weeks ·
**XL** multi-week, spike first.

## 1. Ground truth — what actually executes today

The refine half is real and JAM-shaped; the accumulate half is **three
unreconciled layers pretending to be one**:

- **Refine (real).** Guest `_start` → `run_refine_service`: cold-start via
  `READ(STATE_KEY)` or warm-restart via the `ACTOR_HOLDER` static, FETCH
  dispatch loop, effects buffered (`flush_effects` is a no-op while
  `IN_REFINE`), halt with `RefinePayload{state, reply, effects,
  continue_next}` + ZK io-hash in φ[9..12] (`vos/src/actors/run.rs:438-568`).
- **Layer A — native journal drain (the de-facto accumulate).** The host
  journals mutating hostcalls live and absorbs the halt payload's effects,
  then drains them at end of `tick()` into the in-memory `ServiceStorage`
  map. **No second PVM invocation, ever** (`vos/src/runtime.rs:887-899`).
- **Layer B — durable commit.** After each dispatch the agent thread
  persists exactly one thing: the `STATE_KEY` rkyv blob (plus, for
  Crdt/Raft, an EffectLog node recording the inbound msg + depth-1 INVOKE
  reply bytes) in one redb txn (`vos/src/node.rs:3873-3885`,
  `vos/src/commit.rs:791-874`).
- **Layer C — replicated replay.** Cold start, CRDT merge, and Raft
  follower catch-up delete `STATE_KEY` and **re-execute the entire DAG
  from genesis** through the PVM with recorded INVOKE replies substituted
  (`vos/src/node.rs:1858-1881`). Execution replay was never eliminated —
  it relocated to the replication layer, unbounded (no checkpoints).

**Dead scaffolding, verified.** The guest accumulate
(`run_accumulate_service` → `on_commit` → `replay_effects`) is compiled
into every service ELF via `_KEEP_ACCUMULATE` but is **unreachable from
any entry**: grey-transpiler wires only PC=0 → `_start`
(`grey-transpiler/src/linker.rs:123-130`), `_start` never branches on
φ[7] (no code sets it to 1 anywhere), `operand.rs`'s GP §C.5 encoder has
zero callers, and accumulate gas is decorative. Worse than dead, it is
**semantically wrong**: the host persists `payload.state` on *every*
dispatch (`runtime.rs:801-815`) while `replay_effects` — the path a
conformant JAM host would run — writes state only when `continue_next` is
set (`refine_payload.rs:119-123`). An actor tested on VOS and moved to a
JAM host would silently lose every non-yielding state mutation.
`runtime.rs:54`'s "services work on JAR without modification" is false
today.

**Suspension reality.** `try_poll` polls a handler future exactly once and
*drops it* on Pending — "resume" is always re-run-from-top against rebuilt
state. `ctx.ask` is a synchronous blocking INVOKE (async syntax compiles
to sequential calls). The flat_mem warm-restart exists only for top-level
services (invoke children always cold-start via `new_cached`);
`ContinuationHeader`'s pc/registers fields are written as zeros. `sleep(n)`
encodes a tick count no host path reads. A yield mid-batch **silently
discards** the un-fetched remainder of that tick's messages
(`runtime.rs:739-842`). Cross-node YIELDED is stripped to bare reply
bytes. The one working orchestration pattern — the workspace-excluded
`examples/agents/scheduler` — hand-copies child state into parent state
and cold-reinvokes: that pattern is the germ of the target design.

**Proving reality.** The tracer zero-stubs FETCH/READ/INFO and feeds
inputs only via the `__VOS_WITNESS` patch, so the proved execution is a
*separate checker program's cold start*, not the live invocation — every
provable actor is two programs-in-effect with two commitments
(`extensions/prover/src/lib.rs:50-62` admits this). Only
`H(public, return)` is bound; the RefinePayload the parent actually
commits (state, effects) is unbound. Nothing captures what a later proof
needs (pre-state witnesses); the streaming `verify_chain` drops the
entering-memory-root anchor the in-AIR page-Merkle work paid for.

**Known-bug inventory confirmed en route:** guest panic still commits
same-tick journaled writes (violates the "structurally one commit" claim,
runtime.rs:22-24); external transfers outbox **before** durable commit
(NotLeader ⇒ leaked + duplicated messages); child storage rows /
non-STATE_KEY writes / continuation bodies are never durable;
`blob_by_hash` uses `simple_hash` (a collidable XOR fold) to address
32-byte INVOKE code hashes; `ctx.spawn` never returns the child's
ServiceId; NOW_MS/BOOT_CONTEXT are served live during replay (silent
replica skew); `write_atomic` skips effect-bearing dispatches whose state
blob didn't change (incomplete durable history).

## 2. Verdicts on the vision's assumptions

| Assumption | Verdict |
|---|---|
| "Replay the execution during accumulate" | **Never implemented — and not needed.** JAM's accumulate integrates refine's *results*; it never re-executes refine. Buffered-effects → apply-at-commit is the right model. But re-execution didn't disappear: it lives at the CRDT/Raft merge layer as O(entire-history) replay, which *does* need fixing (checkpoints), and stays legitimately at the proving layer (selective, explicit). |
| Agent actor = JAM service composing stateless refine-only sub-actors | **Right, for a stronger reason than stated**: JAR refine's hostcall set (gas/fetch/historical_lookup/export/**machine**) licenses exactly one composition primitive — nested PVM instantiation. Parent-owned, code-hash-identified, stateless children are the *only* shape that ports. Registry children (own storage row, own ServiceId) structurally cannot. |
| Parent manages suspension/resume of multi-`.await` tasks | **Right goal, wrong mechanism implied.** Retained futures and memory-snapshot resume are both unworkable (futures borrow `&mut actor`; flat_mem snapshots are javm-layout-coupled and JAM-inexpressible). The correct mechanism: **a suspended task is a value** — `TaskRecord{code_hash, state_bytes, pending_msg, step}` in the parent's committed state; resume = cold re-invoke. The scheduler example already proves this shape works. |
| Parent periodically commits its own + sub-actors' state | **Right — and currently fiction.** The durable commit covers only the parent's STATE_KEY blob; everything else evaporates on restart. Under the target model it becomes true *by construction*: Tasks have no storage of their own, so committing the parent commits everything. |
| PVM potentially faster than WASM → near-native actors | **Unevidenced in-tree; drop as a design input.** The only benchmark is grey-JIT vs PolkaVM (PVM-vs-PVM, parity to 3.8×); off Linux/x86-64 VOS falls back to the javm interpreter. Nothing in the agent model needs the claim — per-dispatch cost is dominated by kernel construction + serialization, not straight-line speed. If it's to be marketed, benchmark wasmtime-vs-javm first. |
| Prove concrete things explicitly, not everything refined | **Right, and the cost math mandates it** (~76 segments, ~22 min, 26–29 GB per real proof; streaming verify phone-class). Obligations attach at value boundaries and settlement windows; the accumulate/commit layer is **never** a proof obligation — its trust model is replication. |

## 3. Target design

### 3.1 The work-result contract (one semantic, three consumers)

Make the effect journal **the** work-result. `RefinePayload` v3:

```
{ anchor,                 // commitment to the state refine ran against
                          //   (v1: blake2b of prior STATE_KEY blob; later: SMT root)
  effects[],              // incl. state as an ordinary Effect::Write{STATE_KEY}
  reply, continue_next }
```

- The guest emits its post-dispatch state as an **explicit effect** instead
  of a host special-case — this kills the host/guest state-persistence
  divergence at the root.
- `anchor` is the missing JAM stale-work slot (accumulate can check the
  work-result still applies) and the natural `#[provable]` binding point
  (fold anchor + effects-hash into `bind_io` public bytes).
- Operand-encodable (the already-written `operand.rs` layout) at the FETCH
  boundary, so the same bytes cross a JAM work-package seam unchanged.
- Three consumers apply the identical byte-defined semantic: the native
  host drain (now an *optimization of* a defined semantic, not the only
  truth), the thin guest accumulate (§3.6), and any prover/verifier.

### 3.2 Atomicity and the commit unit

- **Discard-on-panic**: journal scoped per dispatch, dropped whole on guest
  trap (JAM's semantics; restores the "structurally one commit" claim).
- **Commit-then-outbox**: external transfers buffer in the dispatch result
  and route only after `strategy.commit` succeeds; `(agent, seq)` dedupe
  key for idempotent retry.
- **Whole-agent durable unit**: `CommitStrategy::commit` takes the agent's
  full storage delta (parent STATE + any non-STATE writes + continuation
  refs) in one redb txn. Under the Tasks model this is naturally small —
  Tasks have no rows.
- **Suspension vs commit invariant**: the durable commit contains only
  DATA, never execution state. A suspended task *is* its TaskRecord;
  flat_mem continuations remain a host cache whose absence never changes
  semantics. Commit points sit at yield/await boundaries where the guest
  has fully serialized.
- **Determinism enforcement**: gate hostcalls by consistency tier — under
  Crdt/Raft, NOW_MS is *recorded* in the EffectLog and re-served on replay;
  BOOT_CONTEXT entropy is denied by default (manifest opt-in); caller
  trust/role bytes are recorded and replayed as the original identity (not
  trusted-System). Declare each actor's hostcall tier in `.vos_meta`
  (**jam-pure vs vos-only**) so "this agent can also run in JAM" is a
  checkable build-time property, not a comment.
- **Bounded replay**: periodic checkpoint nodes in the DAG/log (full state
  blob at a frontier); soft-restart/cold-start replay from the latest
  checkpoint, not genesis. Effect-bearing dispatches produce a DAG node
  even when the state blob is unchanged (complete durable history — also a
  prerequisite for any prove-from-history story).

### 3.3 The agent model: `vos::agent::Tasks`

One embeddable rkyv field in the parent actor, generalizing the scheduler
example into the framework. One `Child` abstraction, two variants:

- **`Task(code_hash)`** — the primary, JAM-aligned shape: an anonymous
  pure blob, no ServiceId, no storage row, no address. State lives in the
  parent's `TaskRecord`; invocation is in-core during the parent's refine
  (maps to JAR's `machine`); effects fold into the **parent's** keyspace.
  Suspension = the record; resume = cold re-invoke with saved state.
- **`Peer(service_id)`** — a registry agent: own CommitStrategy, own
  ACL/role surface, own network reachability. Driven by asks; cross-node
  yielded-driving waits on the invoke-protocol envelope bump.

**Decision rule**: a child needing its own consistency tier, its own
ACL/role surface, external addressability, or an independent upgrade
lifecycle is a **Peer**. Everything else — computation, long-running jobs,
provable checkers — is a **Task**. (The messenger stays three top-level
agents: msg-log crdt + msg-ctl raft cannot share one parent's commit
domain; that constraint is real and keeps the Peer seam necessary. The
earlier `AgentState` plan mistook JAM's core semantic — children inherit
the parent's commit domain — for a bug; it is exactly what one-service
atomicity means.)

**API**: `spawn(child, msg) → TaskId`; `drive(ctx)` from the tick handler
(re-invokes yielded Tasks with saved state; surfaces
Yielded/Done/Panicked/TooBig distinctly; explicit retry policy — the
scheduler example's silent-drop/resend-forever is what not to do);
`status/cancel/inspect`.

**Multi-`.await` ergonomics**: `vos::task` step-machine combinators now —
a task = ordered idempotent steps + step counter serialized in TaskRecord
state; each step may end in a yield; re-run-from-top is bounded to one
step. A `#[task]` macro reifying restricted async fns into serializable
state machines is later sugar, not a prerequisite.

**Concurrency stance**: concurrency = parent-level task interleaving via
`drive()`, NOT intra-handler concurrent asks. `ctx.ask` stays synchronous
and is documented as such (JAM refine is single-threaded per work item —
intra-handler concurrency buys nothing on the target platform). If
concurrent child I/O ever proves necessary on VOS hosts, the researched
path is porting the extension world's ExecIo retained-task pattern into
the PVM hostcall ABI as a non-blocking INVOKE — an XL spike, only if a
real workload demands it.

**Runtime walls to fix first** (each verified, each breaks the model):
yield-mid-batch mail loss; the 4 KiB invoke output cap surfacing as
STATUS_PANICKED; child-row effect ownership (JAM-inexpressible); spawn's
lost ServiceId; `simple_hash` code addressing (forgeable — must be blake2b
before code-hash-identified Tasks carry any trust).

### 3.4 The unified input ABI (the keystone)

Two challengers independently arrived at the same design from opposite
ends, which is the strongest signal in this review:

> **A Task invocation delivers `(state, msg)` by patching the child's
> initial memory image at a fixed address — the same channel the prover's
> tracer uses (`__VOS_WITNESS`), and the same shape as a JAM work-package
> payload.**

Consequences:

- **Live run ≡ proved run.** The live invocation and the traced
  re-execution start from byte-identical images; the dual-path /
  dual-commitment problem disappears; "prove any recorded invocation" is a
  literal replay of bytes the parent already held. The patching mechanics
  exist today (`trace_blob_with_patches`).
- **JAM-payload-shaped.** The child is FETCH-free and READ-free —
  refine-pure by construction, which is exactly what JAR refine permits.
- **Provable-by-construction.** Every Task is one `#[provable]` attribute
  away from being a proof guest (§3.5); purity is enforced by the ABI, not
  by discipline.

Open sub-question (flagged in §5): whether this witness-delivered mode
eventually subsumes the `[state_len][state][msg]` channel for *all* Tasks
or remains the provable-Task mode only.

### 3.5 The `#[provable]` pipeline

- **`#[provable]` on a pure function** generates a dedicated
  **single-operation proof-guest program**: `witness_buffer!(N)`, a shim
  decoding `(public, secret)`, the annotated fn, `bind_io(public, output)`
  — plus the parent-side typed stub (encode witness, invoke, record). One
  op = one program = one pinned commitment: **no discriminator needed**
  (different ops have different execution shapes and hence different
  commitments anyway — multiplexing bought nothing at the pinning layer).
- **Always-capture, prove-on-demand.** Capture-on-request is infeasible:
  the succinct witness needs *pre*-state that nothing retains. At ask
  time the parent already holds every byte, so capture is nearly free:
  a compact `ProvableRecord{program_commitment, public, blake2b(secret),
  output_digest, root_before, root_after}` (~200 B) in the parent's
  durable commit under **all** consistency tiers; bulky secret witness
  bytes content-addressed into the proof-blob CAS, parent-local,
  GC-by-policy. Proving (~22 min/26–29 GB) happens only on demand.
- **State anchoring** via a framework SMT library (`vos::zk::state`,
  generalizing cipher-clerk's succinct-witness): public =
  `(root_before, root_after, op_digest, output_digest)`; secret = touched
  leaves + paths; the guest reconstructs the roots so verifiers need no
  state access. Parent-owned state makes this *easier* than today's
  hand-rolled clerk pattern — the parent holds the authoritative pre-state
  at exactly the moment the witness is packed.
- **Purity guard**: provable guests reject non-whitelisted hostcalls at
  macro/build level, and the prove-entry traps on any stubbed hostcall
  rather than returning zeros.
- **Pinning tooling** (`vosx zk pin`): build → transpile → representative
  trace → measure {program commitment, canonical profile, seg_steps,
  witness_addr, unpatched image root} → catalog artifact consumed by
  verifiers. Replaces test-file folklore that has already drifted once.
- **Streaming-verify hardening**: port `expected_initial_root` into the
  prover extension's `verify_chain` (the library check exists; the
  deployed path drops it — a ~20-line plumbing gap that currently wastes
  the in-AIR page-Merkle guarantee).
- **Proof-clerk companion** (native extension): consumes ProvableRecords,
  drives `prove_chain`, CASes segments+manifest, answers PVM agents'
  "prove invocation X" asks by message. PVM agents never drive proving by
  hostcall; on-chain agents reference proofs by CAS hash.
- **Obligation layers**: L1 = value crossing a trust boundary
  (Mode::External vouchers — shipped); L2 = settlement windows (amortized,
  async, verified by counterparties or on-chain via the
  settlement-verifier guest); L3 = audit/challenge from captured records.
  Explicitly *never* the accumulate layer.

### 3.6 The JAM parity boundary

Honest division of labor: the VOS host plays **work-package builder +
guarantor + on-chain accumulator**; journal-drain IS accumulate on VOS.
For JAM the apply function must be guest-expressible — but it only needs
to be a *data-application* function, so it is small and cheap (JAM's
accumulate gas is ample for journal application):

- Now: **delete the unreachable scaffolding** (exported `accumulate`
  symbol, `_KEEP_ACCUMULATE`, dead operand encoders as-wired, accumulate
  gas config, all PC=5/φ[7]/dual-entry comments, the false
  `runtime.rs:54` claim, the disabled `tests/pvm.rs`). No aspirational
  comments — four independent readers concluded from the guest code that
  accumulate runs in-PVM; the dead code is actively harmful.
- With the work-result contract (§3.1): the guest accumulate returns as a
  **thin generated APPLY** — decode operand → verify anchor → replay
  effects via real hostcalls → write state unconditionally — reached via
  the **graypaper jump-table entry convention** (decided 2026-07-08:
  converge toward JAM proper — entry 0 = refine, entry 1 = accumulate;
  whether a distinct on_transfer entry exists depends on which graypaper
  revision jar pins, since newer revisions fold transfers into
  accumulate's inputs). Not jar's current φ[7] single-entry select — jar
  aligns toward the jump table instead. Gated by a **parity test** (guest
  accumulate in a PVM over real journals ⇒ byte-identical storage vs the
  native drain). **New jar-repo work item**: grey-transpiler's linker
  currently emits only PC=0 → `_start`; it must learn to emit/dispatch the
  entry table before A15 can land.
- **Conformance harness** when jar's grey-state refine unstubs (today all
  refine hostcalls return WHAT — there is no counterparty to pin against):
  run a Task blob under jar refine semantics, pin the operand/FETCH input
  contract. Until then, the `.vos_meta` hostcall-tier marker keeps
  "jam-pure" a checkable property.

## 4. Migration map (by workstream — see §6 of federation-showcase.md)

Workstream A — vos core (owns `runtime.rs`/`node.rs`/`commit.rs`):

| # | Step | Size |
|---|------|------|
| A0 | Docs/dead-code sweep: PC=5/φ[7]/dual-entry comments, runtime.rs:54, lifecycle.rs:33-42, delete tests/pvm.rs, delete unreachable guest accumulate + `_KEEP_ACCUMULATE` | S |
| A1 | Yield-mid-batch fix: re-queue un-fetched round_items on continue_next; regression test | S |
| A2 | Discard-on-panic: per-dispatch journal scope; panicking handler commits nothing | M |
| A3 | Commit-then-outbox + (agent,seq) dedupe | M |
| A4 | `simple_hash` → blake2b for blob_by_hash / code addressing | S |
| A5 | Break the 4 KiB wall: raise child halt-output cap toward 1 MiB; distinct STATUS_TOO_BIG | M |
| A6 | Fix spawn id loss (deterministic reservation, or delete ctx.spawn in favor of Tasks::spawn + registry install) | S |
| A7 | RefinePayload v3: state-as-effect + anchor; delete host state special-case; parity assertions — **spec frozen: `docs/design/work-result-contract.md`** (incl. journal-overlay anchor chain, §4b child-invoke conversion, clear_continuation rework) | M |
| A8 | Whole-agent durable commit unit (full storage delta in one txn) | L |
| A9 | Invoke-by-code-hash Task mode: no child rows, parent-keyspace effects (co-designed with B5) | L |
| A10 | `vos::agent::Tasks` + port scheduler example into workspace/CI | L |
| A11 | `vos::task` step-machine combinators | M |
| A12 | Determinism tiers: record NOW_MS / deny BOOT_CONTEXT under Crdt/Raft; caller identity in EffectLog; `.vos_meta` hostcall-tier marker | L |
| A13 | DAG checkpointing + effect-bearing-node fix | L |
| A14 | Delete `sleep(n)` tick count (sleep == yield, documented) | S |
| A15 | Guest accumulate as thin APPLY via graypaper jump prologue + parity test + operand wiring — **spec frozen: `docs/design/jam-entry-points.md`**; gated on the jar-side steps there (§4: javm SP/entry_ic, transpiler prologue, guest ports, IC-5 switch) | L (+~M in jar) |
| A16 | Cross-node YIELDED envelope (when a multi-node Peer-driving consumer exists) | M |
| A17 | SPIKE: stale-anchor reconciliation semantics (prereq for parallel refine); SPIKE: non-blocking INVOKE (only if sequential ctx.ask proves limiting) | XL |

Workstream B — proving pipeline (zkpvm, extensions/prover, vos/src/zk.rs,
cipher-clerk):

| # | Step | Size |
|---|------|------|
| B1 | Streaming verify: add expected_initial_root | S |
| B2 | `#[provable]` macro v1 (checker semantics) + witness helpers into vos::zk + port voucher-check | M |
| B3 | `vosx zk pin` catalog tool; migrate e2e off hardcoded constants | M |
| B4 | ProvableRecord capture + CAS secret-witness tier *(after A8/A9)* | L |
| B5 | Witness-delivered INVOKE mode *(co-designed with A9 — the unified ABI)* | L |
| B6 | `vos::zk::state` SMT library (generalize cipher-clerk succinct); rewire clerk flow | L |
| B7 | Proof-clerk companion extension + shared verify template | M |
| B8 | Async prove job (enqueue → job id → CAS publish → callback) — showcase P1 | M |
| B9 | Fix silently-skipping settle tests (stale recursion-verifier paths) — showcase P4 | S |
| B10 | SPIKE: engine-equivalence audit (JIT kernel vs tracing interpreter) — required before claiming live==proved | XL |

## 5. Open decisions (need your call)

1. **jar entry ABI — RESOLVED 2026-07-08**: converge toward JAM proper —
   the graypaper jump-table entry convention (2 entries: refine +
   accumulate; a 3rd on_transfer entry only if the pinned graypaper
   revision keeps it separate). jar/grey aligns to it (grey-transpiler
   entry-table support is the gating work item); the φ[7] select is
   retired along with the rest of the dead scaffolding.
2. **Time/entropy under replication**: recommended NOW_MS = record-and-
   replay, BOOT_CONTEXT = deny under Crdt/Raft with manifest opt-in.
   Confirm or adjust.
3. **Witness ABI scope**: does witness-delivered `(state, msg)` become the
   input channel for ALL Tasks (one ABI, JAM-payload-shaped, everything
   provable-ready) or only for `#[provable]` Tasks? Recommended: all Tasks,
   after A9/B5 land together.
4. **Invoke envelope bound**: pragmatic 1 MiB (matches top-level halt cap)
   vs JAM-derived quantization (work-report ~48 KiB / export segments) as a
   portability guideline. Recommended: 1 MiB cap + document the JAM budget.
5. **Task state durability**: confirmed no per-child storage rows (parent
   TaskRecords are the only durable thing) — flag if any existing actor
   relies on child STORAGE_R across restarts.
6. **Secret-witness retention**: parent-node-local only, hash replicated;
   encryption at rest and GC policy for how long prove-on-request stays
   possible (privacy-platform question).

## 6. Non-goals

- Retained-future or memory-snapshot suspension (unworkable vs PVM borrow
  semantics / javm layout coupling / JAM's no-memory-between-work-items).
- Proving the accumulate/commit layer (its trust model is replication;
  proving it would resurrect the rejected prove-everything design).
- Intra-handler concurrent asks as a near-term ABI (parent-level
  interleaving suffices; ExecIo-to-PVM port is a demand-driven XL spike).
- "PVM faster than WASM" as a design input (unevidenced; nothing depends
  on it; benchmark before marketing).
- Scripted-hostcall tracing as the live/proved unification (every served
  byte becomes unconstrained witness — new soundness work; the
  witness-delivered ABI achieves unification without it).
