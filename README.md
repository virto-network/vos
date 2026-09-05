# VOS

VOS runs signed actors across a group of operator-owned nodes. Actors are
small Rust programs with durable state, typed messages, explicit authority,
and a chosen consistency model.

```mermaid
flowchart LR
    C[Client] --> N[Node]
    N --> R[Published service root]
    N --> G[Agent runtime]
    H[HTTP / SSH] --> N
    R --> A[Actor tree]
    G --> M[Multiple actors]
    R --> S[(Durable state)]
    G --> L[(Linear / Merge / Local lanes)]
    N <--> P[Peer nodes]
    R --> Q[Proof producer]
```

The repository contains one actor programming model and two package targets
during the agent cutover:

- `#[actor]` defines an actor.
- `vosx build` creates a service package (`VOSP`); `space publish` and
  `space install` create the production root service from it.
- `vosx agent build` creates the clean-generation signed `VOS3` package: one
  standard actor PVM plus exact AAS2 state/constructor, AMP2 method-policy,
  AAI1 introspection, and ATD1 Task-dependency artifacts. Agent scheduling and
  any proof-system identity are explicit build inputs. Node-level publication
  of `VOS3` is the next integration boundary; `space publish` intentionally
  rejects it today.
- Both targets use the same actor macros, typed messages, and signed method
  policy. Their host ABIs are authenticated and cannot be cross-packaged.

## Start here

```bash
cargo run -p vosx -- new hello
cargo run -p vosx -- build hello --name hello
cargo run -p vosx -- space new demo
cargo run -p vosx -- space up demo \
  --service-pvm services/vos-service/vos-service.pvm \
  --allow-conformance
```

In another terminal:

```bash
cargo run -p vosx -- space publish demo hello dist/hello.vos
cargo run -p vosx -- space install demo hello --consistency local
cargo run -p vosx -- hello value --space demo
```

See [Getting started](docs/getting-started.md),
[Architecture](docs/architecture.md), and
[Operations](docs/operations.md).

## Repository map

| Path | Purpose |
| --- | --- |
| `vos/` | Actor SDK, service runtime, replication, networking |
| `vosx/` | Build, space, and operator CLI |
| `pvm/` | Bytecode runtime, compiler, codec, and proof system |
| `services/` | Generic service guest and standard agent runtime |
| `actors/` | Platform actors |
| `examples/` | Small supported applications |
| `extensions/` | Trusted request/response host workers |

HTTP and SSH are built-in ingress adapters. HTTP exposes package schemas and
actor methods; SSH serves a semantic terminal for members to discover and
manage the space. Native extensions remain request/response workers called by
actors and never own public listeners.

## Development

```bash
just build-test-artifacts
cargo test --workspace
```

Artifacts committed under `services/` and `vosx/blobs/` are protocol
identities. Rebuild them only through the checked release recipes.

## License

VOS-owned code is licensed under the GNU Affero General Public License,
version 3 or later. The imported PVM crates retain their Apache-2.0 license;
their provenance and license are documented in [`pvm/`](pvm/README.md).
