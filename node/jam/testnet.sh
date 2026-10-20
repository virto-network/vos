#!/usr/bin/env bash
# Services on a local PolkaJam testnet, which this starts and stops:
# - `agent` (the default): the default agent deployed with the counter and
#   the shop, a workflow suspended in one work package and resumed in later
#   ones, every state read witnessed against the root on chain, each batch
#   checked against a VOS node in process (`vos jam testnet`);
# - `statements`: the JAM statements service deployed and driven through
#   its items, each a package submitted by RPC with its extrinsics, its
#   outcome read back (`vos jam statements`);
# - `both`: the agent, then the statements service beside it.
#
# It needs systemd's user manager (`systemd-run --user`, `systemctl
# --user`), `setsid`, `curl`, and the programs built: the agent and the test
# actors (`just build-agent build-test-actors`) for the agent, the service
# (`just check-no-std`, or `just jam-statements-testnet`) for the
# statements. POLKAJAM names the directory of PolkaJam's binaries, v0.8.0
# by default (sha256 e90c8ccd… of its release archive); the run's files go
# to a new directory under TMPDIR (or /tmp), or JAM_RUN, and the testnet's
# chain under TMPDIR too. The testnet runs PolkaJam's interpreter: its
# recompiler needs vm.unprivileged_userfaultfd=1. It logs in UTC, as the
# record's times are.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
mode="${1:-agent}"
case "$mode" in agent|statements|both) ;; *) echo "usage: $0 [agent|statements|both]" >&2; exit 2 ;; esac
POLKAJAM="${POLKAJAM:-$HOME/.cache/vos/polkajam/v0.8.0/polkajam-v0.8.0-linux-x86_64}"
scratch="${TMPDIR:-/tmp}"
run="${JAM_RUN:-$(mktemp -d "$scratch/vos-jam-testnet.XXXXXX")}"
mkdir -p "$run/builder"
rpc="localhost:19800"
unit="vos-jam-testnet-$$"
vos="${CARGO_TARGET_DIR:-$root/target}/debug/vos"
agent="${CARGO_TARGET_DIR:-$root/agent/default/target}/riscv64em-vos/release/vos-agent.elf"
actors="${CARGO_TARGET_DIR:-$root/agent/test-actors/target}/riscv64em-vos/release"
service="${CARGO_TARGET_DIR:-$root/target}/riscv64em-vos/release/statement-service.elf"

for binary in polkajam-testnet polkajam jamt; do
    [ -x "$POLKAJAM/$binary" ] || { echo "no $binary in $POLKAJAM" >&2; exit 1; }
done
if [ "$mode" != statements ]; then
    [ -f "$agent" ] && [ -f "$actors/lean.elf" ] || {
        echo "build the agent and the test actors first: just build-agent build-test-actors" >&2
        exit 1
    }
fi
if [ "$mode" != agent ]; then
    [ -f "$service" ] || {
        echo "build the statements service first: just check-no-std" >&2
        exit 1
    }
fi
if curl -s -m 2 -o /dev/null "http://$rpc"; then
    echo "something already answers on $rpc: stop it first" >&2
    exit 1
fi

cargo build -q -p vos-cli --manifest-path "$root/Cargo.toml"

# The testnet runs in a scope of its own, which stopping stops every
# process of; the process groups in it are recorded, and signalled too
# should the scope be gone. Stopped on exit, whatever the outcome.
groups() {
    local cgroup
    cgroup="$(systemctl --user show -p ControlGroup --value "$unit.scope" 2>/dev/null || true)"
    [ -n "$cgroup" ] && [ -r "/sys/fs/cgroup$cgroup/cgroup.procs" ] || return 0
    xargs -r -n1 ps -o pgid= -p <"/sys/fs/cgroup$cgroup/cgroup.procs" 2>/dev/null | sort -u || true
}
stop() {
    local group chain
    systemctl --user stop "$unit.scope" 2>/dev/null || true
    for group in $(cat "$run/testnet.groups" 2>/dev/null); do
        kill -TERM -- "-$group" 2>/dev/null || true
    done
    echo "testnet stopped (process groups: $(tr '\n' ' ' <"$run/testnet.groups" 2>/dev/null))"
    # The chain's own files, which the testnet keeps in a directory of its own.
    chain="$(sed -n 's/^testnet: Working directory: //p' "$run/testnet.log" 2>/dev/null | head -n1)"
    case "$chain" in "$scratch"/testnet-*) rm -rf "$chain" ;; esac
}
trap stop EXIT

setsid systemd-run --user --scope -q --unit="$unit" -p MemoryMax=12G -p MemorySwapMax=0 \
    env TZ=UTC TMPDIR="$scratch" POLKAVM_BACKEND=interpreter "$POLKAJAM/polkajam-testnet" >"$run/testnet.log" 2>&1 &

rpc_call() {
    curl -s -m 10 -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":[]}" "http://$rpc" || true
}
for _ in $(seq 120); do
    groups >"$run/testnet.groups"
    if rpc_call syncState | grep -q '"Completed"'; then
        break
    fi
    sleep 1
done
rpc_call syncState | grep -q '"Completed"' || { echo "the testnet never came up" >&2; exit 1; }
groups >"$run/testnet.groups"
echo "testnet up: process groups $(tr '\n' ' ' <"$run/testnet.groups"); log $run/testnet.log"

{
    echo "PolkaJam: $POLKAJAM"
    "$POLKAJAM/polkajam" --version
    "$POLKAJAM/jamt" --version
    echo "backend: interpreter"
} | tee "$run/build.txt"

status=0
if [ "$mode" != statements ]; then
    "$vos" jam testnet \
        --polkajam "$POLKAJAM" \
        --rpc "$rpc" \
        --agent "$agent" \
        --actors "$actors" \
        --data "$run/builder" | tee "$run/vos.log" || status=$?
fi
if [ "$mode" != agent ] && [ "$status" = 0 ]; then
    "$vos" jam statements \
        --polkajam "$POLKAJAM" \
        --rpc "$rpc" \
        --service "$service" \
        --fixtures "$root/pvm/proof/fixtures" \
        --data "$run/statements" | tee "$run/statements.log" || status=$?
fi

# What the testnet said of the packages it did not take.
for record in "$run/builder/record.txt" "$run/statements/record.txt"; do
    [ -f "$record" ] || continue
    {
        echo "the testnet's errors:"
        grep ' ERROR ' "$run/testnet.log" || echo "  none"
    } | tee -a "$record"
done
echo "run: $run"
exit "$status"
