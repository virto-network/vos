# vosx

The VOS operator CLI: create spaces, run their daemons, publish and
install agents, and onboard new nodes — each with one short command.

Everything space-related lives under `vosx space *`. Every command
takes `--format json` for scripts and LLMs; `vosx help-schema` dumps
the full CLI as JSON.

## Quick start

The space-registry infrastructure is bundled into the binary. Application
actors are built as signed `.vos` v2 packages; the registry stores those
exact package bytes and never retranspiles an ELF:

```bash
cargo build -p vosx

# build the protocol-pinned generic service PVM
(cd services/vos-service && cargo +nightly actor)
target/debug/vosx service-pvm \
  services/vos-service/target/riscv64em-javm/release/vos_service.elf \
  --out dist/vos-service.pvm

# build one canonical actor PVM and its signed package
target/debug/vosx build examples/actors/counter \
  --name counter \
  --service-pvm dist/vos-service.pvm

# create a space (identity + genesis) and boot its daemon
target/debug/vosx space new demo
target/debug/vosx space up demo --service-pvm dist/vos-service.pvm &

# publish + install the immutable package, then talk to it
target/debug/vosx space publish demo counter:0.1.0 dist/counter.vos
target/debug/vosx space install demo counter:0.1.0
target/debug/vosx space call demo counter increment by=1

# the ergonomic sibling — dynamic dispatch against any agent's schema
target/debug/vosx --space demo counter value

target/debug/vosx space info demo          # liveness, endpoint, bootnode hint
target/debug/vosx space down demo          # SIGTERM the daemon
```

## Onboard a second node

An invite token is a self-contained credential: it embeds the space
id, bootnodes, a role, and an expiry, signed by an admin. The joiner
needs nothing else — no config, no manifest exchange.

```bash
# admin — mint a token (defaults: --role member, --expires 7d)
vosx space invite demo

# joiner — join + boot + auto-redeem, one command
vosx space up "vos1…" &          # or `vosx space up -` to pipe the token in
```

The joiner syncs the registry and spawns the agents its role admits.
Tokens grant `member` or `developer`; admins are promoted explicitly
with `space role grant` after admission. Audit redemptions with
`vosx space invite demo list` (rows appear when a token is redeemed)
and invalidate a token with `… revoke <token_pub-prefix>`.

## Recipes

A recipe is a TOML snapshot of a space — a dev-time convenience,
never the source of truth (the registry is). It is consumed once at
genesis or reconciled explicitly:

```bash
vosx space new demo --recipe space.toml   # bank for the first `space up`
vosx space up space.toml                  # or create+boot straight from one
vosx space apply demo space.toml --diff   # preview a reconcile (dry run)
vosx space apply demo space.toml          # publish/install what's missing
vosx space export demo > snapshot.toml    # live registry → recipe
```

`apply` is idempotent — re-applying the same recipe is all-skips.
Application entries name an explicit immutable signed package with
`program = "name:version"`; legacy lifecycle bytes are rejected.
`--upgrade` re-points the instances.

## Command map

| Group | Commands |
|---|---|
| Lifecycle | `new` · `up` · `down` · `list` · `info` · `forget` |
| Onboarding | `invite` (`list`/`revoke`) · `members` · `role` |
| Catalog | `publish` · `install` · `upgrade` · `uninstall` · `unpublish` · `programs` · `agents` · `describe` |
| State & ops | `apply` · `export` · `subs` · `caps` · `raft-status` · `call` |

`space call` is the floor primitive — any agent, any handler; the
catalog verbs are typed sugar over the same plumbing. `vosx whoami`
prints the operator identity that signs admin operations.

## More

- Repo overview + actor/extension authoring: [`../README.md`](../README.md)
- Example recipes: [`../examples/`](../examples/)
- Extension cookbook: [`../extensions/AUTHORING.md`](../extensions/AUTHORING.md)
