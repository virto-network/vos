# Actors and packages

Actors are deterministic Rust state machines. A handler reads its own state,
receives an authenticated origin, and returns a reply plus durable effects.

## Package contents

A `.vos` package always contains:

- the actor PVM;
- typed method schemas;
- role policies;
- optional Task dependencies;
- a deployment signature.

A service package (`VOSP`) additionally binds the generic service program and
is accepted by `space publish`. An agent package (`VOSK`) additionally signs
its execution entry, state-lane schema, and runtime requirements; the agent
driver installs it into an existing agent. The two envelopes cannot be
cross-packaged.

The package is the installation unit. Raw ELFs and PVMs are build inputs, not
deployable applications.

## Agent actors

Agent actors opt into the lane-aware source ABI on both macros:

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

- `examples/actors/counter`: smallest standard-agent actor.
- `examples/actors/shared-board`: linear and convergent state in one
  standard-agent actor.
- `examples/actors/workflow`: service actor with durable calls and suspension.
- `examples/actors/private-age`: service actor with private input and an
  attested result; `age-gate` is its native verifier.
