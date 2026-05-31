# Operating VOS in Production

A short runbook for shipping `vosx` to a real host or
container — what to install, what to configure, how to
inspect and debug a running daemon.

This chapter doesn't repeat the [architecture overview] or
[extensions guide]; it's strictly operator-facing. If you
want to *write* an actor, see [SDK & DevX]; if you want to
understand *how* the runtime replicates state, see
[Replication].

[architecture overview]: ./architecture.md
[extensions guide]: ./extensions.md
[SDK & DevX]: ./sdk.md
[Replication]: ./replication.md

## What "production" means here

A daemon process that:

- Boots from a deterministic state across restarts.
- Survives `kill -TERM` cleanly (no lost commits, no
  leaked endpoint files).
- Rejects unknown peers by default (no remote code
  execution by drive-by libp2p dialers).
- Refuses host syscalls that an extension didn't declare
  it needs.
- Can be deployed as a self-contained container image.

Everything below is the operator's surface area for those
guarantees. None of it requires writing Rust.

## Install paths

| Path | When |
|---|---|
| **Container** (`containers/Dockerfile`) | Production. Self-contained, no host toolchain. |
| **`cargo install --path vosx`** | Dev box. Fast iteration; needs nightly + a clone of the repo. |
| **`cargo install vosx` from crates.io** | Not yet — blocked on jar.git's crates.io publication. |

For anything past local-dev experimentation, use the
container. The rest of this chapter assumes you've got
either a built `vosx:slim` image (per [container packaging]
in the repo) or a local `vosx` binary on `$PATH`.

[container packaging]: https://github.com/virto-network/vos/tree/master/containers

## First-time setup

```sh
# 1. Operator identity — auto-created on first `vosx` invocation
#    at $XDG_CONFIG_HOME/vosx/identity.key. The PeerId is your
#    long-lived handle; the registry's `auth_grants` table keys
#    admin grants on it.
vosx whoami

# 2. Create a space. Generates per-space libp2p keypair under
#    $XDG_DATA_HOME/vosx/<space_id>/, records the operator's
#    PeerId as the bootstrap admin, commits the genesis event.
vosx space new --name demo

# 3. Boot the daemon. On first boot it consumes the
#    admin-bootstrap file and grants AUTH_ROLE_ADMIN to your
#    PeerId. Subsequent boots are idempotent.
vosx space up demo
```

The persistent identity is the only piece that lives outside
the space data dir — multiple spaces on the same machine share
one operator identity (matched to `$XDG_CONFIG_HOME`).

## Running in a container

The reference setup is in [`containers/`] at the repo root.
The quickstart:

```sh
docker compose -f containers/ai-daemon.yml up -d
docker compose -f containers/ai-daemon.yml logs -f vosx
```

The compose file maps three named volumes (data, config,
cache) and a libp2p port on 4001. The container's first boot
runs `space new` automatically, so you get a working daemon
with no prior config.

[`containers/`]: https://github.com/virto-network/vos/tree/master/containers

### Secrets via `$env:VAR`

Manifest string values matching `$env:NAME` are resolved at
boot time against the daemon's environment. Use this to keep
secrets out of the manifest file:

```toml
[[extension]]
name = "ai"
path = "/usr/local/lib/vosx/libai_extension.so"
[extension.init]
hf_token = "$env:HF_TOKEN"
```

Then:

```sh
HF_TOKEN=hf_... docker compose -f containers/ai-daemon.yml up
```

`$env:NAME` referencing an unset variable is a fatal error at
boot — secrets going missing should be loud, not silent.

### Volumes that must persist

| Mount | Contents | Lose it = ? |
|---|---|---|
| `/var/lib/vosx`   | space data dir(s), agent redbs, `.endpoint`, `node.key` | reset all installed agents |
| `/etc/vosx`       | operator's `identity.key`, `spaces.toml` index          | rebuild admin enrollment from scratch |
| `/var/cache/vosx` | blob cache, hf-hub model cache                          | re-download models (~400MB for the AI default) |

Resetting `/etc/vosx` means a fresh operator identity, which
means the daemon's `auth_grants` won't recognise you anymore.
Either back it up or re-run `space new` to rebootstrap.

## Identity, members, and auth

Per-agent ACLs (M0-M10, 2026-05-30) put role checks at the
*actor* layer instead of the host. Each actor declares its
own role hierarchy via `type Role` + `const SPACE_ROLE_MAP`;
the macro emits a check at the dispatch boundary that runs
before the handler body. Refusals surface as
`STATUS_FORBIDDEN` on the wire and "permission denied" at the
vosx surface.

There are two scopes:

- **Space-level**: a coarse role (`guest | member | developer
  | admin`) that applies across every actor in the space via
  the actor's `SPACE_ROLE_MAP`. The common case.
- **Actor-local**: a per-`(peer, agent)` override stored in
  the registry's `actor_acls` table. Useful for "Bob is a
  regular Member but I need him to maintain dev-project."

The flow:

1. The operator has a persistent libp2p PeerId (`vosx whoami`).
2. `space new` auto-enrols the creator as space-level Admin on
   first boot via the `admin_bootstrap.txt` mechanism.
3. Every libp2p-arriving call carries the caller's PeerId
   bytes. The host probes the registry for both grants and
   passes them through to the actor.
4. The actor's macro-emitted check picks the higher-precedence
   grant (actor-local first, then space-level via the actor's
   map) and refuses if the result is below the handler's
   declared `#[msg(role = X)]` threshold.

### Inspect the current grants

```sh
vosx space role demo list                   # space-level
vosx space role demo list --in dev-project  # actor-local for dev-project
```

### Add an admin

```sh
TEAMMATE_PEER="12D3KooW..."

vosx space role demo grant "${TEAMMATE_PEER}" admin
```

Each new admin can then `space role grant <other> <role>`
recursively. Space-level role hierarchy:
`admin > developer > member > guest`.

### Add an actor-local override

When a peer needs elevated access in just one actor:

```sh
# Grant raw role byte 2 on dev-project — discriminant of the
# dev-project actor's Role enum (Maintainer = 2 in its source).
vosx space role demo grant "${TEAMMATE_PEER}" 2 --in dev-project
```

Actor-local roles are bytes the CLI doesn't try to name — look
up the discriminant in the target actor's `Role` enum. The
override takes precedence over the space-level grant for that
actor only; all other actors still see the space-level role.

### Revoke a grant

```sh
vosx space role demo revoke "${TEAMMATE_PEER}"                  # space-level
vosx space role demo revoke "${TEAMMATE_PEER}" --in dev-project # actor-local only
```

The actor-local revoke leaves the space-level grant intact.

### Anyone vs nobody

A peer with no grant defaults to `guest`. They can:

- Read public handlers (`programs`, `agents`, `members`,
  `auth_grants`, `peer_role`, `meta_for_instance`).
- Run `vosx whoami`, `vosx space role <space> list`.

They cannot:

- Publish programs, install agents, change membership, grant
  roles, upload blobs — any handler annotated
  `#[msg(role = ...)]` in its actor.

If a non-admin tries a gated operation the daemon emits:

```
WARN vos::node: auth: actor refused call — caller lacks the required role target=<svc_id> peer=12D3KooW...
```

and the vosx client prints:

```
error: registry.grant_role(): permission denied: caller lacks the required role
```

### Extension relay caps (`intra_caps`)

Native extensions are **relays, not principals**. When an extension
makes an outbound call to another actor (e.g. the dev extension
calling `space-registry.publish`), the daemon forwards the *caller
that invoked the extension* — not the extension's own identity — and
bounds it by the extension's declared `intra_caps`. The effective
authority of a relayed call is:

```
min(caller's space role, the extension's declared ceiling for the target)
```

So an extension can never amplify the caller, and the caller can
never reach actors the extension didn't declare.

Declare caps in the manifest as `"actor:role"` strings:

```toml
[[extension]]
name = "dev"
path = "/usr/local/lib/vosx/libdev_extension.so"
# The dev extension's `publish` lands programs in the registry's
# Admin-gated catalog, so it must relay up to Admin there.
intra_caps = ["space-registry:admin"]
```

- **No `intra_caps`** (the default) → every outbound call relays as
  `Caller::Unauthenticated`, so role-gated handlers refuse it. An
  extension that only reads ungated handlers needs no caps.
- **Wildcards**: `"space-registry:*"` (any role on that actor),
  `"*:developer"` (developer on every actor), `"*"` / `"*:*"` (any
  role on any actor — a fully-trusted relay). The daemon logs a loud
  warning at `space up` for any-actor wildcards; prefer naming each
  target explicitly.

At boot the daemon logs each extension's effective caps, so `vosx
space up` output is the source of truth for what an extension may
relay:

```
INFO vosx: extension 'dev' intra_caps: space-registry:admin
INFO vosx: extension 'gateway' intra_caps: (none — outbound calls relay as Unauthenticated)
```

The bound applies regardless of who called the extension: a `member`
operator who triggers the dev extension's `publish` is still refused
at the registry, because their `member` role (not the extension's
trust) is what gets relayed, capped by the declared ceiling.

### HTTP gateway and anonymous traffic

The http-gateway proxies external HTTP into the daemon. Because the
relay default is now deny (no `intra_caps` → `Caller::Unauthenticated`),
the gateway is safe out of the box: its outbound calls carry
`Caller::Unauthenticated`, so role-gated handlers reject anonymous
HTTP traffic while read-only handlers (`resolve`, `agent_names`,
`meta_for_instance`) stay open. The legacy `relay_unauthenticated =
true` flag is now a deprecated synonym for "declare no caps" — keep
it for back-compat, but it has no effect beyond clearing any caps.

## Capability policy

Every extension declares the host facilities it uses in its
`service_main!(caps = [...])` block. The daemon enforces these
at the host ABI boundary per the `cap_policy` set in the
manifest:

```toml
# Top-level — applies to every extension.
cap_policy = "block"

# Per-extension override.
[[extension]]
name = "ai"
cap_policy = "log"
```

| Policy | Behaviour |
|---|---|
| `block` (default) | Refuse the syscall with `HOST_ERR_CAP_DENIED`. |
| `log`             | Allow + emit `tracing::warn!` once per cap. |
| `kill`            | Refuse + flip the extension's shutdown flag. |

The `log` setting is useful during initial rollout to
inventory what your extensions actually use without blocking
production traffic. Sprint 1 shipped only `log`; Sprint 2
flipped the default to `block`.

Only the host-ABI-gated caps (`net.libp2p.dial`, etc.) are
enforced today. `fs.*` and `process.*` caps stay declarative
and depend on the container sandbox (drop-all capabilities,
read-only root FS — both already set in the compose file).

### Inspect what an extension declared

```sh
vosx --verbose space up demo 2>&1 | grep "declared capabilities"
```

```
INFO vos::node: extension: declared capabilities id=svc:820e:13148 actor=ext::AiExtension caps=["fs.cache","net.http.outbound","net.libp2p.dial","tokio-runtime"]
```

If a cap warn fires, the extension's manifest needs the
missing entry — or the policy needs relaxing for that
extension specifically.

## Health & signals

### Healthcheck

The compose file uses a filesystem-based check: the daemon
writes `<data_dir>/.endpoint` once libp2p binds a listen
address. `find /var/lib/vosx -name .endpoint -mmin -1` is the
liveness probe. No new HTTP surface, no dependency on
`http-gateway`.

### Graceful shutdown

`docker stop`, `kill -TERM <pid>`, and Ctrl-C all hit the same
`vosx::shutdown::install` handler (Sprint 1 commit C). The
daemon:

1. Flips an `AtomicBool` that `node.run_forever()` polls every
   50ms.
2. Run-loop exits, returns to `space up`.
3. Cleanup deletes `.endpoint`, agents flush, process exits 0.

Typical wall-clock latency: <1s. Bounded by Docker's
`stop_grace_period` (10s default) under load.

### Force-kill

If the daemon is wedged (rare; usually a CRDT replay deadlock
or an extension that's panicking in a loop), `kill -KILL` is
safe — the redb is journaled, state survives an unclean
shutdown. The `.endpoint` file may be stale; the next
`vosx space *` invocation detects this and removes it.

## Common operations

```sh
# What's installed?
vosx space agents demo

# What programs are in the catalog?
vosx space programs demo

# Inspect a single agent's schema (msg names, arg types).
vosx space describe demo counter

# Direct invoke (the floor primitive — every typed wrapper is
# sugar on this).
vosx space call demo counter inc

# Subscribe filter — per-node opt-out of expensive agents.
vosx space subs demo --add big-actor

# Shut it down.
vosx space down demo
```

All commands support `--format json` for scripting + LLM
consumption.

## Troubleshooting

### `no daemon running for space '<name>'`

The `.endpoint` file says no daemon is alive. Either:

- The daemon crashed without cleanup. Check
  `journalctl` / `docker logs`. The endpoint file is auto-
  cleaned on the next CLI call.
- The space exists in `spaces.toml` but you've never started
  it. Run `vosx space up <name>`.

### `auth: refusing privileged registry handler`

A non-admin called a gated handler. Either:

- Grant them `admin`: `vosx space role <space> grant <peer> admin`.
- Run the call from an enrolled identity (`vosx whoami`
  to see who you are).

### `cap-overage: extension used host facility outside its declared caps`

Either:

- Add the missing cap to the extension's `service_main!`
  block.
- Relax the policy for that one extension:
  `[[extension]] cap_policy = "log"` in the manifest.

### `couldn't reach daemon (prefix 0x...)` from a CLI

libp2p connectivity issue. Common causes:

- Container's port mapping doesn't expose 4001/tcp.
- Host firewall blocks loopback libp2p traffic.
- Daemon hasn't finished binding yet — retry after a second.

### Daemon won't start: `genesis mismatch`

A prior space data dir is being booted against a different
`spaces.toml` entry. Either delete the data dir for a fresh
start, or update the entry to point at the right space_id.

### Daemon won't start: `is not set in the daemon's environment`

A `$env:VAR` in the manifest references an unset env var. Set
it before `space up`, or remove the indirection. Per Sprint 3,
missing secrets are fatal — better than silently passing an
empty string.

## What this chapter doesn't cover

- **Writing extensions** — see [`extensions.md`].
- **Replication semantics** — see [`replication.md`].
- **Threat model + privacy goals** — see [`threat-model.md`].
- **Kubernetes deployment** — out of scope; docker-compose
  covers single-host, and ops folks who want k8s typically
  bring their own helm chart.
- **Backup / disaster recovery** — the redb is journaled and
  the merkle-CRDT means any other replica can supply missing
  state, but a per-space backup policy is operator choice.

[`extensions.md`]: ./extensions.md
[`replication.md`]: ./replication.md
[`threat-model.md`]: ./threat-model.md
