#!/bin/sh
# vosx container entrypoint.
#
# Boots `vosx space up` for the space named by VOSX_SPACE,
# auto-creating the space on first run when it doesn't yet
# exist. tini (PID 1) forwards SIGTERM to this script; this
# script `exec`s vosx so signal handling lands directly in the
# daemon (vosx::shutdown::install — Sprint 1 commit C).
#
# Required env vars:
#   VOSX_SPACE        — space name. Required.
#
# Optional env vars:
#   VOSX_MANIFEST     — path to manifest TOML inside the image
#                       or via volume mount. Defaults to
#                       /etc/vosx/manifest.toml.
#   VOSX_LISTEN       — additional libp2p listen multiaddrs,
#                       comma-separated.
#   VOSX_CONNECT      — additional bootnode multiaddrs.
#   RUST_LOG          — tracing-subscriber filter. Default: info.
#
# Compose-side configuration goes through env vars so a
# container deployment can keep secrets (HF tokens, …) out of
# the manifest file via `$env:VAR` indirection (Sprint 3).

set -eu

: "${VOSX_SPACE:?VOSX_SPACE env var is required (the space name to boot)}"
: "${VOSX_MANIFEST:=/etc/vosx/manifest.toml}"
: "${RUST_LOG:=info}"
export RUST_LOG

# Ensure XDG dirs exist before the daemon writes into them.
mkdir -p \
    "${XDG_DATA_HOME:-/var/lib/vosx}" \
    "${XDG_CONFIG_HOME:-/etc/vosx}" \
    "${XDG_CACHE_HOME:-/var/cache/vosx}"

# Auto-create on first boot. `vosx space list --format json`
# returns an empty array if the space isn't registered yet.
# Note: `space new` records the operator's PeerId in
# admin_bootstrap.txt; the daemon consumes it on first
# `space up` to enrol the container as admin (Sprint 2 commit
# B2). The image's persistent identity lives at
# $XDG_CONFIG_HOME/vosx/identity.key, so volumes persist this
# across restarts.
if ! /usr/local/bin/vosx space list --format json 2>/dev/null \
        | grep -q "\"name\":\"${VOSX_SPACE}\""; then
    echo "[entrypoint] space '${VOSX_SPACE}' not registered locally; running 'space new'..." >&2
    /usr/local/bin/vosx space new --name "${VOSX_SPACE}"
fi

# Build the `space up` arg list. Extra --listen / --connect
# flags are space-separated in the env var.
SPACE_UP_ARGS="space up ${VOSX_SPACE}"
if [ -f "${VOSX_MANIFEST}" ]; then
    SPACE_UP_ARGS="${SPACE_UP_ARGS} --manifest ${VOSX_MANIFEST}"
fi
if [ -n "${VOSX_LISTEN:-}" ]; then
    for addr in ${VOSX_LISTEN}; do
        SPACE_UP_ARGS="${SPACE_UP_ARGS} --listen ${addr}"
    done
fi
if [ -n "${VOSX_CONNECT:-}" ]; then
    for addr in ${VOSX_CONNECT}; do
        SPACE_UP_ARGS="${SPACE_UP_ARGS} --connect ${addr}"
    done
fi

# `exec` so tini ⇒ vosx is direct: SIGTERM lands in the daemon
# (no shell middle layer), and vosx's `shutdown::install`
# handler flips the AtomicBool that `run_forever` watches.
echo "[entrypoint] launching: vosx ${SPACE_UP_ARGS}" >&2
exec /usr/local/bin/vosx ${SPACE_UP_ARGS}
