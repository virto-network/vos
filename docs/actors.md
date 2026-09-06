# Actors and packages

Actors are deterministic Rust state machines. A handler reads its own state,
receives an authenticated origin, and returns a reply plus durable effects.

## Package contents

A `.vos` package always contains:

- the actor PVM;
- typed method schemas;
- authorization/method policies;
- optional Task dependencies;
- a deployment signature.

A legacy service package (`VOSP`) additionally binds the generic service
program and is accepted by `space publish`. A portable AgentActor package
(`VOS3`) signs an exact closure containing the actor PVM, AAS2 state and
constructor contract, AMP2 method policy, AAI1 introspection, ATD1 Task set,
and every referenced Task PVM. It uses a raw Ed25519 producer key/signature and
derives its deployment identity from those signing bytes. The two envelopes
cannot be cross-packaged; host publication of `VOS3` remains a separate
cutover.

The package is the installation unit. Raw ELFs and PVMs are build inputs, not
deployable applications.

## Portable AgentActors

Portable AgentActors opt into the lane-aware source ABI on both macros and run
inside an Agent:

```rust,ignore
#[actor(agent)]
pub struct Board {
    title: String,              // Linear
    edits: crdt::Counter,       // Merge
    #[state(local)] draft: String,
}

#[messages(agent)]
impl Board {
    #[msg(linear)]
    pub fn rename(&mut self, title: String) { self.title = title; }

    #[msg(merge)]
    pub fn record_edit(&mut self) {
        self.edits.increment(1).expect("one stable operation per slice");
    }

    #[msg]
    pub fn title(&self) -> String { self.title.clone() }
}
```

The generated method view exposes only the lanes permitted by its mode. The
runtime independently projects the same lanes before execution and rejects a
transition that changes any other lane. Service actors continue to use plain
`#[actor]` and `#[messages]`.

An Agent method that names an actor or Space role also supplies its portable,
nonzero role identity; packages are not bound to the destination Space:

```rust,ignore
#[msg(
    query,
    space_role = SpaceRole::Member,
    space_role_id = "3131313131313131313131313131313131313131313131313131313131313131"
)]
pub fn status(&self) -> Status { /* ... */ }
```

`vosx actor build --scheduling` explicitly signs scheduler requirements.
Attested methods or provable Task dependencies require one exact nonzero
`--proof-system <64-lowercase-hex>` identity; supplying it when unused is an
error. The `agent` namespace is reserved for Agent operations, not actor
authoring.

## Actor trees

A root actor may spawn package-authorized children. Calls use bound handles,
so both the destination service and actor identity remain authenticated.
Child state stays private to the service and is exposed only to the child that
owns it.

## Tasks and proofs

A Task is a package-pinned computation used by an actor. A recorded Task can
produce a public claim and producer-private witness material. The witness is
kept outside replicated state; a proof producer later turns it into a portable
proof. See [Authority and privacy](security.md).

## Examples

- `examples/actors/counter`: smallest portable AgentActor.
- `examples/actors/shared-board`: linear and convergent state in one
  portable AgentActor.
- `examples/actors/workflow`: service actor with durable calls and suspension.
- `examples/actors/private-age`: service actor with private input and an
  attested result; `age-gate` is its native verifier.
