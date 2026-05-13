# vosx — container packaging

Multi-stage Dockerfile + docker-compose for shipping vosx as a
self-contained container image. Sprint 3 of the production-
readiness roadmap (see
`memory/project_container_packaging_plan.md` for the design
rationale).

## What's in the image

`vosx:slim` (~200MB compressed) bundles:

- The `vosx` release binary at `/usr/local/bin/vosx`.
- The AI extension `.so` at `/usr/local/lib/vosx/libai_extension.so`.
- The bundled space-registry + dev-project actor ELFs that
  `vosx` ships at `vosx/blobs/` (used by `space new` / `dev new`
  without external dependencies).
- `tini` for proper PID-1 signal forwarding.

Deliberately not included:

- The `riscv64em-javm` Rust toolchain. Adding it gives the
  `dev` extension's `compile` handler what it needs to build
  PVM actors from source — but ~1.8GB of weight for one
  workflow. A `vosx:dev` variant will add this if there's
  demand.
- The `http-gateway` extension. Its release profile hangs in
  fat-LTO (`project_publish_cleanup_landed` D2); re-add the
  `-p http-gateway` cargo flag in the Dockerfile once that's
  fixed.

## Quick start

```sh
# From the workspace root:
docker compose -f containers/ai-daemon.yml up -d
docker compose -f containers/ai-daemon.yml logs -f vosx
```

The container auto-creates a space named `demo` on first boot
(via the entrypoint's `space new` fall-through) and starts
listening on libp2p port 4001. Persistent state lives in three
named volumes — see the compose file for the exact shape.

To run a CLI command against the running daemon:

```sh
docker compose -f containers/ai-daemon.yml exec vosx \
    vosx ai generate --space demo --max-tokens 64 \
    "Reply with OK."
```

The first generate call downloads the default ~400MB GGUF model
into the cache volume.

## Image variants

- `vosx:slim` (default) — admin + AI workflows.
- `vosx:dev` — not yet built. Adds cargo + nightly + the
  riscv64em-javm target for the `dev` extension's compile
  path. Open issue.

## Secrets via env-var indirection

Manifest string values matching `$env:NAME` are resolved
against the daemon's environment at boot (Sprint 3). Use this
to keep API tokens out of the manifest file:

```toml
[[extension]]
name = "ai"
path = "/usr/local/lib/vosx/libai_extension.so"
init = { hf_token = "$env:HF_TOKEN", ... }
```

then:

```sh
HF_TOKEN=hf_... docker compose -f containers/ai-daemon.yml up
```

The reconciler errors at startup if `$env:NAME` references an
unset variable, so a missing secret is loud rather than silent.

## Volumes

| Path             | XDG dir          | Persists?       |
|------------------|------------------|-----------------|
| /var/lib/vosx    | XDG_DATA_HOME    | Required        |
| /etc/vosx        | XDG_CONFIG_HOME  | Required        |
| /var/cache/vosx  | XDG_CACHE_HOME   | Recommended     |

`/etc/vosx` holds the operator's persistent libp2p identity
(`identity.key`). Sprint 2's daemon-auth gate keys admin
grants on this PeerId, so resetting `/etc/vosx` between
container restarts requires a fresh `space new` (which auto-
enrols the new identity).

## Healthcheck

The compose file's `healthcheck:` block uses a filesystem
probe — the daemon writes `<data_dir>/.endpoint` once
libp2p has bound a listen address. Cheap, no new HTTP
surface. See option (c) in
`project_container_packaging_plan` for the trade-off
analysis.

## Smoke test

`containers/tests/smoke.sh` builds the image, boots the
compose stack, probes `vosx whoami` from inside, sends
SIGTERM, asserts clean exit. Skips with status 0 when docker
isn't available, so CI without docker doesn't fail.

```sh
bash containers/tests/smoke.sh
```

Doesn't run automatically — invoke during release prep.

## Signal handling

`tini` (PID 1) → `vosx-entrypoint` → `exec vosx space up …`.
Both `docker stop` (SIGTERM) and `Ctrl-C` interactively
trigger Sprint 1's `vosx::shutdown::install` handler, which
flips the AtomicBool that `node.run_forever` polls. Clean
exit in <1s on a quiet daemon; up to the SIGKILL grace
period (10s default) under load.
