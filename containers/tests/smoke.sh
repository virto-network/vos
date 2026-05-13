#!/usr/bin/env bash
# vosx:slim container smoke test.
#
# Verifies the container actually boots and the daemon's HTTP
# surface (well, libp2p endpoint) becomes reachable. Doesn't
# attempt a full `vosx ai generate` round-trip — that takes a
# ~400MB model download on first run + ~25s of inference, which
# is too heavy for a release-prep smoke. The compose
# healthcheck is what we exercise.
#
# Skips with status 0 when:
#   - docker isn't installed.
#   - the docker daemon isn't reachable.
# So CI environments without docker don't fail the test.
#
# Run from the workspace root:
#   bash containers/tests/smoke.sh

set -eu

cd "$(dirname "$0")/../.."

# ── Skip-if-no-docker ──────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
    echo "smoke.sh: docker not installed; skipping (exit 0)."
    exit 0
fi
if ! docker info >/dev/null 2>&1; then
    echo "smoke.sh: docker daemon not reachable; skipping (exit 0)."
    exit 0
fi

IMAGE_TAG="${VOSX_IMAGE_TAG:-vosx:slim-smoke-$$}"
COMPOSE_PROJECT="vosx-smoke-$$"
COMPOSE_FILE="containers/ai-daemon.yml"

cleanup() {
    echo "smoke.sh: cleaning up compose project ${COMPOSE_PROJECT}..." >&2
    docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true
    docker image rm -f "${IMAGE_TAG}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ── 1. Build the image ─────────────────────────────────────────
echo "smoke.sh: building ${IMAGE_TAG}..."
docker build -f containers/Dockerfile -t "${IMAGE_TAG}" .

# ── 2. Boot compose stack ──────────────────────────────────────
# Override the image: tag so we point at the just-built one
# instead of vosx:slim. The override goes through compose's
# image: field by setting it after the fact via env-var.
echo "smoke.sh: starting compose stack..."
VOSX_IMAGE="${IMAGE_TAG}" docker compose \
    -p "${COMPOSE_PROJECT}" \
    -f "${COMPOSE_FILE}" \
    up -d

# ── 3. Wait for healthcheck ────────────────────────────────────
# Container is healthy when `.endpoint` exists under
# /var/lib/vosx — the daemon writes it once libp2p binds.
echo "smoke.sh: waiting for daemon health (60s timeout)..."
deadline=$(( $(date +%s) + 60 ))
while [ "$(date +%s)" -lt "${deadline}" ]; do
    status="$(docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" ps --format json 2>/dev/null | head -1 || true)"
    case "${status}" in
        *'"Health":"healthy"'*) break ;;
        *) sleep 2 ;;
    esac
done

# Final check.
if ! docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" ps --format json \
        | grep -q '"Health":"healthy"'; then
    echo "smoke.sh: daemon never became healthy. Logs:" >&2
    docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" logs vosx >&2 || true
    exit 1
fi
echo "smoke.sh: daemon healthy."

# ── 4. Smoke-test the CLI through `docker exec` ───────────────
echo "smoke.sh: probing 'vosx whoami' from inside the container..."
if ! docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" exec -T vosx \
        /usr/local/bin/vosx whoami --format json 2>&1 \
        | grep -q '"peer_id"'; then
    echo "smoke.sh: vosx whoami didn't return a peer_id. Failing." >&2
    docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" logs vosx >&2 || true
    exit 1
fi
echo "smoke.sh: vosx whoami succeeded."

# ── 5. SIGTERM exits cleanly ───────────────────────────────────
echo "smoke.sh: stopping daemon via SIGTERM..."
start=$(date +%s)
docker compose -p "${COMPOSE_PROJECT}" -f "${COMPOSE_FILE}" stop vosx
elapsed=$(( $(date +%s) - start ))
if [ "${elapsed}" -gt 30 ]; then
    echo "smoke.sh: stop took ${elapsed}s — slow but ok if non-zero exits cleanly." >&2
fi

# Verify the exit code was 0.
exit_code="$(docker inspect -f '{{.State.ExitCode}}' "${COMPOSE_PROJECT}-vosx-1" 2>/dev/null || echo "?")"
if [ "${exit_code}" != "0" ]; then
    echo "smoke.sh: daemon exited with ${exit_code} on SIGTERM (expected 0)." >&2
    exit 1
fi

echo "smoke.sh: PASSED. Daemon booted, served a CLI call, and shut down cleanly."
exit 0
