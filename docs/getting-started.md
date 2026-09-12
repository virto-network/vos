# Getting started

The current `vosx` surface deliberately separates buildable clean-generation
primitives from lifecycle operations that are not connected yet. You can
create and run a local Space, author AgentActor packages, inspect local
extension policy, and perform verified offline backup/restore. There is no
compatibility fallback for creating or operating Agents.

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
producer identities. Building a package does not install it; operational Agent
and actor lifecycle commands remain unavailable until ordinary-Agent genesis
issuance/finality and lifecycle wiring are complete. Automatic system bootstrap
does not create an application Agent or remove that current limitation.

## Back up a stopped Space

```bash
vosx space backup demo /var/backups/vos/demo-2026-09-10
vosx space restore /var/backups/vos/demo-2026-09-10 \
  --node-key /secure/demo-node.key
```

Backup is fail-closed and never archives the node identity secret. Retain that
key separately. The command refuses unsupported live Agent/service generations
rather than copying opaque stores as if they were portable.

See [Actors and packages](actors.md) for the package boundary and
[Operations](operations.md) for the current operational gate.
