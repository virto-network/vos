# Getting started

Install Rust and the repository toolchain, then build the CLI and platform
artifacts:

```bash
just build-test-artifacts
cargo build -p vosx
```

## Create a portable AgentActor

```bash
cargo run -p vosx -- actor new counter
```

The generated AgentActor has ordinary Rust state and typed handlers:

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

    #[msg(capability = "counter.write")]
    pub fn add(&mut self, amount: u64) {
        self.value += amount;
    }

    #[msg(query)]
    pub fn value(&self) -> u64 {
        self.value
    }
}
```

Build a signed package:

```bash
cargo run -p vosx -- actor build counter --name counter
```

The output package commits to the actor program, method schemas, policies,
Task dependencies, and signer. It is a portable `VOS3` package hosted by an
Agent; `agent` is reserved for operations and is not an authoring alias.

## Start the current production space runtime

Start a local space:

```bash
cargo run -p vosx -- space new demo
cargo run -p vosx -- space up demo \
  --service-pvm services/vos-service/vos-service.pvm \
  --allow-conformance
```

The current production `space publish` path accepts legacy `VOSP` service
packages and rejects the `VOS3` produced above. Publishing portable
AgentActors is the next Agent-integration boundary.

For installed production services, assign package capabilities through
editable space roles. A member can use the same stable identity through
several HTTP tokens and SSH keys:

```bash
vosx space role demo define operator --power 150 \
  --capability counter.write --capability agent.invoke \
  --operation-key define-operator-1
vosx space role demo grant me --role member --role operator \
  --operation-key grant-me-operator-1
vosx space access demo issue-ssh ~/.ssh/id_ed25519.pub --expires 30d
```
