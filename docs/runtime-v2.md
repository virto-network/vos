# VOS runtime v2 contract

> Implementation status: the versioned contracts, guest service state tree,
> canonical `vos-service.pvm` Refine/Accumulate entries, package tooling, actor
> APIs, and CRDT primitives described here are present. The local v2 harness
> executes both phases through that PVM and commits only an accepted guest
> result; it has no native transition-apply shortcut. The production node still
> runs the legacy runtime while durable v2 scheduling and backend integration
> are completed. Legacy node behavior is not evidence of v2 conformance.

Before that production cutover, guest Install must authenticate
`genesis.authorization` against consensus-authoritative deployment state, and
`PROGRAM_LOOKUP` availability must be pinned to or imported from
consensus-visible state rather than a node-local cache. A bounded reclamation
or checkpoint plan for unreachable SMT and CRDT DAG nodes is also required
before the engine stores production state.

VOS v2 assigns one logical JAM service to a root actor and its owned child
tree. The protocol-pinned `vos-service.pvm` is one generic program with the
Gray Paper two-slot entry prologue: Refine begins at instruction counter 0 and
Accumulate at instruction counter 5. Registers `φ[7]`/`φ[8]` remain the
standard argument pointer/length window; they are never VOS phase selectors.
Actor packages contain application PVMs, not application-written Refine or
Accumulate functions.

Refine is pure. A `WorkEnvelopeV2` imports the exact deployment, program,
state, continuation pages, authorization evidence, causal base and referenced
blobs needed to run a slice. Refine may only return a `TransitionV2`; it cannot
write service storage or expose a reply. Identical bytes and execution
semantics produce an identical transition.

Accumulate validates service and ABI identity, the canonical actor
`ProgramId`, authorization, base revision or causal dependencies, blob and
proof availability, and invocation deduplication. It commits state or CRDT
operations, continuations, inbox/outbox rows and the receipt atomically.
Replies, outbound calls and proof packages become visible only after that
commit. A stale linear transition is rejected intact for rescheduling.

## Continuations

An await checkpoint stores the exact nested kernel: each VM's program hash,
PC, registers, heap bounds, gas and lifecycle, mutable capabilities, dirty
page hashes, active/runnable scheduler state, nested call stack and the pending
protocol boundary. Resume consumes the checkpoint, injects one result into its
declared registers and continues at `resume_pc`. It never restarts the handler
at PC 0. Suspended actors are non-reentrant; later messages remain queued.

Every await is a durable slice boundary. Effects before it may commit even if a
later slice fails, so multi-await handlers have saga semantics. Same-tree calls
may execute inline. Cross-root calls always use durable outbox/inbox rows and a
`CallId` derived from `(InvocationId, await ordinal)`.

## Packages and identity

`.vos` v2 packages bind the service ABI, execution-semantics ID, canonical
actor PVM and its `ProgramId`, interfaces, role policies and schemas. Optional
ELF/source-map data is diagnostic only. `DeploymentId` excludes diagnostics
and signatures but includes the authoritative manifest and PVM bytes.
Registries store these bytes and never retranspile an ELF. JIT products,
proving keys and traces are caches keyed by `ProgramId`.

The infrastructure PVM is committed at
`services/vos-service/vos-service.pvm`; its identity is
`VOS_SERVICE_PROGRAM_ID`. To reproduce it, build and validate the guest:

```sh
cd services/vos-service
cargo +nightly actor
cd ../..
cargo run -p vosx -- service-pvm \
  services/vos-service/target/riscv64em-javm/release/vos_service.elf \
  --out target/vos-service.pvm
```

The guest build remaps its checkout directory and pins Rust crate metadata so
path-derived symbol hashes cannot perturb the linked program. The v2 service
integration gate transpiles a fresh ELF and requires byte identity with the
committed PVM, in addition to checking its pinned `ProgramId` and GP entry
layout.

This is a clean storage and wire break. A v1 store or package must be reset and
reinstalled; there is no v1 decoder or migration in a v2 service.

## CRDT boundary

Only `#[actor(crdt)]` packages may select CRDT consistency. Their replicated
fields use explicit `vos::crdt` merge rules (`Value`, `Map`, `Set`, `List`,
`Text`, `Counter`). Stable logical operation IDs and causal metadata replace
wall clocks. The Merkle-DAG supplies causal transport and persistence, not
convergence for arbitrary commands.

Concurrent scalar assignments retain alternatives through `conflicts()` while
choosing the same visible value; counter increments, list and text operations
merge without dropping a DAG branch. Constraints such as uniqueness,
overdraft prevention or irreversible global ordering require Raft or a
purpose-built conflict-free construction.

One workflow slice derives one CRDT `ChangeId` from its stable service, actor,
`InvocationId`, and workflow step—not from its observed heads. The change also
commits the complete `WorkEnvelopeV2` hash. An exact retry therefore reuses the
original envelope bytes, including its causal base; changing that base is new
work and must not masquerade as a retry of the old input.

Within a change, the scheduler assigns every actor execution a unique dispatch
ordinal. Field operations are canonical in `(ActorId, dispatch ordinal,
operation ordinal)` emission order; their hashed `OperationId` is a dedup key,
not an ordering key. A continuation resume carries the new dispatch namespace
in its checkpoint token and resets the restored actor-local allocator before
post-await guest code executes. This prevents both stale pre-await change IDs
and repeated ordinal-zero allocation when an actor is dispatched again.
