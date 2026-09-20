# Getting started

You can create and run a local Space, author AgentActor packages, and on Linux
create a Local Agent and install a signed actor. This is a disposable-test
checkpoint, not production sign-off: startup and operations remain slow,
ordinary Shared-Agent genesis/finality is not connected, and further recovery
and proof gates remain. See [current status](agent-saga-status.md). There is no
compatibility fallback for older Agent generations.

## Create and run a Space

```bash
vosx space new demo
vosx space list
vosx space info demo
vosx space up demo
```

`space up` runs in the foreground. From another terminal, stop it cleanly:

```bash
vosx space down demo
```

`space new` prepares the bundled runtime and system actor packages, signed by
the Space root, and creates `local.toml` with HTTP on `127.0.0.1:8080` and SSH
on `127.0.0.1:2222`. The first `space up` installs Authority and Catalog before
reporting readiness; restart reopens those installations. No manual system
package installation is needed. If either port is already occupied, change
that listener in the Space's `local.toml` before starting it. The default
listeners are local-only, and enabling ingress does not grant anonymous access.

Use `space up --once` only as an idle-exit smoke mode. Listen and startup peer
addresses are accepted through repeatable `--listen` and `--connect` options.
Persistent listen addresses, native extensions, and ingress listeners live in
the Space data directory's node-local `local.toml`.

## Author a portable AgentActor

```bash
vosx actor new board
vosx actor build board --name board
```

The scaffold uses the public lane-aware SDK. `actor build` creates a signed
`VOS3` package with exact program, schema, policy, dependency, capability, and
producer identities. Building a package does not install it. Automatic system
bootstrap prepares Authority and Catalog, not an application Agent.

## Create a Local Agent and install an actor (Linux)

With `space up demo` running and ready in another terminal:

```bash
vosx space create-local-agent demo
```

The command reports the full Agent ID and a verified creation acknowledgement.
To try the maintained Counter from a repository checkout, build its package,
then replace `AGENT_HEX` below with that reported ID:

```bash
vosx actor build examples/actors/counter --name counter --out-dir dist
vosx space install-local-actor demo AGENT_HEX dist/counter.vos --name counter
```

Counter requires no constructor input. Other packages may require exact encoded
`--constructor-data`; arbitrary text or JSON is not a substitute. Installation
must report a verified acknowledgement before being treated as complete.
Earlier checkpoints recorded multi-second Create and Install operations; those
historical timings do not qualify the current binary. Consult the
[current evidence](agent-saga-status.md) for the tested revision and open latency gates.

Do not issue a new operation to retry an uncertain result. Preserve the client
request stores and use the command's `--resume` option with the same coordinates.
A timeout or unsigned HTTP error does not prove failure. Historical Create
replay after Install may return409 because server retention is bounded; inspect
the retained signed evidence. See [Operations](operations.md) for invocation and
recovery boundaries.

## Backup limitation after first startup

The Space initialized by this walkthrough cannot currently use `space backup`,
even after a clean stop and before installing any application actors. First
startup automatically creates `system-agent`, which the registry-only portable
backup format deliberately refuses.

The backup/restore commands support only registry-only, pre-native Spaces;
native Agent portable export and restore remain unfinished. Do not work around
the refusal by deleting system stores or treating a raw copy as a supported
portable backup. Keep the node identity secret separately: portable backup
never archives it. Use disposable data for this checkpoint's testing.

See [Actors and packages](actors.md) for the package boundary and
[Operations](operations.md) for the current operational gate.
