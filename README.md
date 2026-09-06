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

The CLI exposes one clean-generation authoring surface for portable
AgentActors hosted by an Agent:

- `#[actor(agent)]` and `#[messages(agent)]` define a portable AgentActor.
- `vosx actor new` scaffolds an AgentActor project.
- `vosx actor build` creates its signed `VOS3` package: one actor PVM plus
  exact AAS2 state/constructor, AMP2 method-policy, AAI1 introspection, and
  ATD1 Task-dependency artifacts. Scheduling and any proof-system identity are
  explicit build inputs.
- `agent` is reserved for Agent operations; it is not an authoring alias.

Legacy service packages (`VOSP`) remain part of the production runtime during
the cutover, but no longer have a top-level authoring command. Node-level
publication of `VOS3` is the next integration boundary; `space publish`
intentionally rejects it today.

## Start here

```bash
cargo run -p vosx -- actor new hello
cargo run -p vosx -- actor build hello --name hello
cargo run -p vosx -- space new demo
cargo run -p vosx -- space up demo \
  --service-pvm services/vos-service/vos-service.pvm \
  --allow-conformance
```

The build writes `dist/hello.vos`. It is a portable AgentActor package, not a
legacy service package; installation follows the Agent publication cutover
described above.

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
