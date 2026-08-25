# Getting started

Install Rust and the repository toolchain, then build the CLI and platform
artifacts:

```bash
just build-test-artifacts
cargo build -p vosx
```

## Create an actor

```bash
cargo run -p vosx -- new counter
```

The generated actor has ordinary Rust state and typed handlers:

```rust
use vos::prelude::*;

#[actor]
pub struct Counter {
    value: u64,
}

#[messages]
impl Counter {
    fn new() -> Self {
        Self { value: 0 }
    }

    #[msg]
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
cargo run -p vosx -- build counter --name counter
```

The output package commits to the actor program, method schemas, policies,
Task dependencies, and signer.

## Run it in a space

Start a local space:

```bash
cargo run -p vosx -- space new demo
cargo run -p vosx -- space up demo \
  --service-pvm services/vos-service/vos-service.pvm \
  --allow-conformance
```

Publish, install, and call the actor:

```bash
cargo run -p vosx -- space publish demo counter dist/counter.vos
cargo run -p vosx -- space install demo counter --consistency local
cargo run -p vosx -- counter add amount=4 --space demo
cargo run -p vosx -- counter value --space demo
```

Use `--consistency raft` for one ordered replicated state machine, or
`--consistency crdt` for convergent operation history.
