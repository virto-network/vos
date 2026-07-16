# vosx

The VOS operator CLI: create spaces, run their daemons, publish and
install agents, and onboard new nodes — each with one short command.

Everything space-related lives under `vosx space *`. Every command
takes `--format json` for scripts and LLMs; `vosx help-schema` dumps
the full CLI as JSON.

## Quick start

The space-registry and the `dev-project` agent are bundled into the
binary, so a fresh checkout needs no artifact builds:

```bash
cargo build -p vosx           # once; binary at target/debug/vosx

# create a space (identity + genesis) and boot its daemon
vosx space new demo
vosx space up demo &

# publish + install an agent, then talk to it
vosx space publish demo --bundled dev-project
vosx space install demo dev-project:0.1.0
vosx space call demo dev-project list_branches

# the ergonomic sibling — dynamic dispatch against any agent's schema
vosx --space demo dev-project list_branches

vosx space info demo          # liveness, endpoint, bootnode hint
vosx space down demo          # SIGTERM the daemon
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
Changed agent content must name an explicit immutable
`program = "name:version"`; `--upgrade` re-points the instances.

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
