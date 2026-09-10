# VOS

VOS is a runtime for durable Agents hosted on operator-controlled nodes. An
Agent owns an immutable profile, a runtime, a replica set, explicit authority,
and a forest of signed actors. The clean-generation host contracts and the
standard AgentRuntime are implemented in this repository.

This branch is an intentional CLI cutover. `vosx` currently exposes actor
authoring plus local Space lifecycle; it does not expose Agent creation,
installation, invocation, membership, or recovery commands. Those operations
return only when the clean system authority and catalog bootstrap path can own
them end to end. No legacy service executable or dynamic command fallback is
used in the interim.

## Local Space lifecycle

```bash
vosx space new demo
vosx space list
vosx space info demo
vosx space up demo
vosx space down demo
```

`space up` runs in the foreground. `space backup` and `space restore` provide
the currently supported verified offline recovery boundary; run `--help` for
their required paths and node-key handling. `space caps` inspects only local
native-extension policy.

## Author an actor

```bash
vosx actor new board
vosx actor build board --name board
```

`actor build` writes a signed `VOS3` envelope containing the program and its
exact schemas, policies, dependencies, capabilities, producer identity, and
signature. It does not install the package.

Read [Getting started](docs/getting-started.md),
[Architecture](docs/architecture.md), [Actors and packages](docs/actors.md),
and [Operations](docs/operations.md).

## Repository map

| Path | Purpose |
| --- | --- |
| `vos-agent-sdk/` | public no-std Agent contracts and wire formats |
| `vos/` | Agent hosts, replication, networking, and ingress |
| `vosx/` | actor authoring and local Space CLI |
| `actors/` | clean system actors and retained registry bootstrap actor |
| `services/agent-runtime*` | standard AgentRuntime sources |
| `pvm/` | standard-program runtime, compiler, and proof implementation |
| `examples/` | maintained actor and custom-runtime examples |

## Development

```bash
just clean-break-check
cargo test --workspace --lib -- --test-threads=1
```

Committed artifacts under `vosx/blobs/` are protocol identities. Reproduce
and verify them only through the checked release recipes.

## License

VOS-owned code is licensed under the GNU Affero General Public License,
version 3 or later. Imported PVM crates retain their Apache-2.0 license; their
provenance and license are documented in [`pvm/`](pvm/README.md).
