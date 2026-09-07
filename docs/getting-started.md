# Getting started

The released `vosx` binary contains the standard AgentRuntime and the system
authority and catalog actors. No external runtime program is needed.

## Create a Space

```bash
vosx space new demo
vosx space up demo
```

`space up` runs the node in the foreground. Keep it running and use a second
terminal for the remaining commands.

## Create an empty Agent

```bash
vosx agent create demo notes --profile shared
vosx agent list demo
vosx agent show demo/notes
```

The Agent is useful before it contains an actor: it already has a stable
`AgentId`, immutable profile, runtime, resource policy, and replica set.
Creation authority is profile-specific:

- Members may create Private Agents.
- Developers may create Private and Local Agents.
- Admins may create Private, Local, and Shared Agents.

## Author and install an actor

```bash
vosx actor new board
vosx actor build board --name board
vosx actor install demo/notes board/dist/board.vos --name board
vosx agent show demo/notes
```

The generated actor uses the public lane-aware SDK:

```rust,ignore
use vos::prelude::*;

#[actor(agent)]
pub struct Counter {
    value: u64,
}

#[messages(agent)]
impl Counter {
    fn new() -> Self {
        Self { value: 0 }
    }

    #[msg(linear)]
    fn add(&mut self, amount: u64) -> u64 {
        self.value = self.value.saturating_add(amount);
        self.value
    }

    #[msg]
    fn value(&self) -> u64 {
        self.value
    }
}
```

`actor build` writes one signed `VOS3` package containing the program and its
exact schemas, policies, dependencies, capabilities, producer identity, and
signature.

## Call and manage the actor

```bash
vosx call demo/notes/board add --amount 3

vosx actor suspend demo/notes/board
vosx actor resume demo/notes/board
vosx actor upgrade demo/notes/board board/dist/board-new.vos
vosx actor remove demo/notes/board
```

Removal succeeds only when the actor is a leaf and has no queued work,
continuation, messages, retained result, proof artifact, or other lifecycle
debt.

## Try the other profiles

```bash
vosx agent create demo scratch --profile local
vosx agent create demo companion --profile private
```

A Local Agent stays on one exact Node. A Shared Agent is discoverable and can
combine Raft-ordered Linear state, convergent Merge state, and replica-local
state. A Private Agent is owner-only, absent from the shared catalog, encrypted
at rest and in synchronization, and accepts only Merge and Local actor state.

To add or remove one of the owner's exact Nodes:

```bash
vosx agent invite-node demo/companion --node <full-NodeId>
vosx agent revoke-node demo/companion --node <full-NodeId>
```

See [Actors and packages](actors.md) for state lanes and custom runtimes, and
[Operations](operations.md) for backups, recovery, and release checks.
