# Actors and packages

Actors are deterministic Rust state machines. A handler reads its own state,
receives an authenticated origin, and returns a reply plus durable effects.

## Package contents

A `.vos` package contains:

- the actor PVM;
- typed method schemas;
- role policies;
- optional Task dependencies;
- the generic service program identity;
- a deployment signature.

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

- `examples/actors/counter`: smallest local actor.
- `examples/actors/shared-board`: convergent shared state.
- `examples/actors/workflow`: durable calls and suspension.
- `examples/actors/private-age` and `age-gate`: private input with an attested
  result.

