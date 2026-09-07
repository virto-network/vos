# Actors and packages

An actor is a deterministic program installed into an Agent. It receives an
authenticated Principal origin with separate Node provenance, reads only the
state views allowed by its method mode, and returns a reply plus proposed
effects. The AgentRuntime validates those effects before anything becomes
durable.

## One package envelope

Every deployable `.vos` file is a canonical signed `VOS3` envelope with one
explicit kind:

- `Actor`
- `AgentRuntime`

An Actor package commits to its standard actor program, actor ABI requirement,
state-lane schemas, method metadata and policies, Task dependencies, required
optional runtime capabilities, producer identity, and Ed25519 signature. It
does not pin a particular AgentRuntime.

An AgentRuntime package commits to its outer standard program, mandatory
management ABI, supported actor ABI range, lanes and optional capabilities,
control-schema identity, limits, migration policy, producer, and signature.
The host rejects noncanonical encodings, omitted artifacts, duplicate content
aliases, signer/producer mismatches, unknown fields, and every earlier package
generation.

Raw ELF and PVM files are build inputs, not installation units.

## Lane-aware state

```rust,ignore
use vos::prelude::*;

#[actor(agent)]
pub struct Board {
    title: String,                 // Linear
    edits: crdt::Counter,          // Merge
    #[state(local)] draft: String, // Local
    #[state(const)] board_id: u64, // immutable
    #[state(skip)] cached: usize,  // derived
}

#[messages(agent)]
impl Board {
    #[msg(linear)]
    fn rename(&mut self, title: String) {
        self.title = title;
    }

    #[msg(merge)]
    fn record_edit(&mut self) {
        self.edits.increment(1).expect("one stable operation");
    }

    #[msg(local)]
    fn save_draft(&mut self, draft: String) {
        self.draft = draft;
    }

    #[msg]
    fn title(&self) -> String {
        self.title.clone()
    }
}
```

Ordinary persisted fields default to Linear, `crdt::*` fields imply Merge,
and ordinary `#[storage]` is Linear unless explicitly typed or marked
otherwise. The macros generate a mode-specific view, so a forbidden lane
access is a compile error. The runtime also compares lane commitments before
and after execution and rejects cross-lane mutation independently.

Queries return observation metadata containing the Linear revision, Merge
frontier, and Local revision used. `#[msg(linearizable)]` first obtains a
Linear read barrier. A Linear method may emit an `after_commit_merge` message;
delivery is durable and exactly once, but deliberately occurs after the Linear
commit rather than in one cross-lane transaction.

## Actor forest and lifecycle

An Agent starts with an empty forest. Managers install top-level actors;
actors may spawn package-authorized owned children. Stable actor identity is
separate from its mutable name and current deployment.

```bash
vosx actor install demo/notes board.vos --name board
vosx actor upgrade demo/notes/board board-new.vos
vosx actor suspend demo/notes/board
vosx actor resume demo/notes/board
vosx actor remove demo/notes/board
```

Upgrade preserves identity while changing the exact deployment under a signed
lifecycle transition. Removal is rejected unless the actor is a leaf and has
no continuation, inbox, outbox, scheduled work, unacknowledged result, retained
proof, or other debt. A fresh install after removal receives a new incarnation
and installation identity; an old request cannot resurrect the removed actor.

An Agent directory can contain far more actors than one execution slice. The
runtime keeps at most 63 inner machines live simultaneously. If an inline call
chain would exceed the limit, it records a continuation and resumes in a later
slice.

## Calls and exactly-once results

```bash
vosx call demo/notes/board add-task --id 1 --text "Ship it"
```

Calls bind the full Space, Agent, actor incarnation and deployment, method,
mode, authenticated Principal, Node provenance, and invocation identity. An
exact retry returns the retained terminal result without executing again.
Result acknowledgement is itself durable. Same-Agent calls may run inline;
cross-Agent calls always use durable await, timeout, retry, and late-reply
records.

## Roles and authority

Method policies use portable nonzero role identities. A Space may map its
built-in roles to actor roles without changing the signed package. Management
and invocation evidence binds the exact request and deployment context, and is
verified by every runtime replica before mutation.

There is no ambient signing ability. The maintained `local-signer` example
stores an installation secret in an explicit Local actor. A Shared workflow
first calls that actor to obtain a context-bound signature, then submits the
signature as visible input to a second operation.

## Tasks, proofs, and scheduling

A Task is a package-pinned computation. An attested method or provable Task
declares one exact proof-system identity. Public proof records bind the outer
runtime, inner actor, method and mode, exact work and transition, and lane
commitments. Producer-private witnesses are never encoded into replicated
state or a proof record.

Scheduling is optional runtime behavior. The maintained custom runtime orders
ready work deterministically by `(due_slot, priority, schedule_id)`. Local
work receives a durable monotonic observation; Shared work commits the
leader's observation. Repeating schedules advance from their previous due
slot, avoiding drift and duplicate execution across restart or leadership
transfer.

## Maintained examples

- `examples/actors/counter`: Linear counter.
- `examples/actors/shared-board`: hybrid Linear and Merge board.
- `examples/actors/private-notes`: Merge-only Private companion.
- `examples/actors/local-signer`: explicit Local signer.
- `examples/agent-runtimes/custom-linear`: signed scheduled runtime.
