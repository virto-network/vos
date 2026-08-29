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
