#!/usr/bin/env bash
# Services on a local PolkaJam testnet, which this starts and stops:
# - `agent` (the default): the default agent deployed with the counter and
#   the shop, a workflow suspended in one work package and resumed in later
#   ones, every state read witnessed against the root on chain, each batch
#   checked against a VOS node in process (`vos-jam-dev testnet`);
# - `statements`: the JAM statements service deployed and driven through
#   its items, each a package submitted by RPC with its extrinsics, its
#   outcome read back (`vos-jam-dev statements`);
# - `both`: the agent, then the statements service beside it;
# - `chain`: the end to end on chain, `vos-node`'s `chain` test, its
#   testnet's clock the host's shifted by the eight bytes (milliseconds,
#   little-endian) of a file the test writes (`clock-shift.c`, preloaded
#   into the testnet's nodes): so the chain's time passes `MaxRootAge`
#   within the run.
#
# It needs systemd's user manager (`systemd-run --user`, `systemctl
# --user`), `setsid`, `curl`, and the programs built: the agent and the test
# actors (`just build-agent build-test-actors`) for the agent, the service
# (`just check-no-std`, or `just jam-statements-testnet`) for the
# statements, and for `chain` the host's C compiler (`cc`) and the test
# actors, the default agent and the representative (`just
# build-test-actors build-agent build-representative`). POLKAJAM names the directory of PolkaJam's binaries, v0.8.0
# by default (sha256 e90c8ccd… of its release archive); the run's files go
# to a new directory under TMPDIR (or /tmp), or JAM_RUN, and the testnet's
# chain under TMPDIR too. The testnet runs PolkaJam's interpreter: its
# recompiler needs vm.unprivileged_userfaultfd=1. It logs in UTC, as the
# record's times are.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
mode="${1:-agent}"
case "$mode" in agent|statements|both|chain) ;; *) echo "usage: $0 [agent|statements|both|chain]" >&2; exit 2 ;; esac
POLKAJAM="${POLKAJAM:-$HOME/.cache/vos/polkajam/v0.8.0/polkajam-v0.8.0-linux-x86_64}"
scratch="${TMPDIR:-/tmp}"
run="${JAM_RUN:-$(mktemp -d "$scratch/vos-jam-testnet.XXXXXX")}"
mkdir -p "$run/builder"
rpc="localhost:19800"
unit="vos-jam-testnet-$$"
dev="${CARGO_TARGET_DIR:-$root/target}/debug/vos-jam-dev"
agent="${CARGO_TARGET_DIR:-$root/agent/default/target}/riscv64em-vos/release/vos-agent.elf"
actors="${CARGO_TARGET_DIR:-$root/agent/test-actors/target}/riscv64em-vos/release"
service="${CARGO_TARGET_DIR:-$root/target}/riscv64em-vos/release/statement-service.elf"

for binary in polkajam-testnet polkajam jamt; do
    [ -x "$POLKAJAM/$binary" ] || { echo "no $binary in $POLKAJAM" >&2; exit 1; }
done
if [ "$mode" = agent ] || [ "$mode" = both ]; then
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

# The testnet's clock: the host's, shifted by the file's milliseconds.
clock=()
if [ "$mode" = chain ]; then
    cc -O2 -shared -fPIC -o "$run/clock-shift.so" "$root/tools/jam-dev/clock-shift.c" -ldl
    head -c 8 /dev/zero >"$run/clock-shift"
    clock=(LD_PRELOAD="$run/clock-shift.so" VOS_CLOCK_SHIFT="$run/clock-shift")
else
    cargo build -q -p vos-jam-dev --manifest-path "$root/Cargo.toml"
fi

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
    env TZ=UTC TMPDIR="$scratch" POLKAVM_BACKEND=interpreter "${clock[@]}" "$POLKAJAM/polkajam-testnet" >"$run/testnet.log" 2>&1 &

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
if [ "$mode" = chain ]; then
    env VOS_E2E_RUN="$run" VOS_E2E_RPC="$rpc" POLKAJAM="$POLKAJAM" VOS_E2E_SERVICE="$service" \
        VOS_CLOCK_SHIFT="$run/clock-shift" VOS_E2E_TESTNET_LOG="$run/testnet.log" \
        cargo test -p vos-node --features chain --test chain --manifest-path "$root/Cargo.toml" \
        run:: -- --nocapture --test-threads=1 2>&1 | tee "$run/chain.log" || status=$?
    # The test captures its standard error: a failure's message is there.
    [ "$status" = 0 ] || grep -A8 panicked "$run/stderr" || true
fi
if [ "$mode" = agent ] || [ "$mode" = both ]; then
    "$dev" testnet \
        --polkajam "$POLKAJAM" \
        --rpc "$rpc" \
        --agent "$agent" \
        --actors "$actors" \
        --data "$run/builder" | tee "$run/vos.log" || status=$?
fi
if { [ "$mode" = statements ] || [ "$mode" = both ]; } && [ "$status" = 0 ]; then
    "$dev" statements \
        --polkajam "$POLKAJAM" \
        --rpc "$rpc" \
        --service "$service" \
        --fixtures "$root/pvm/proof/fixtures" \
        --data "$run/statements" | tee "$run/statements.log" || status=$?
fi

# What the testnet said of the packages it did not take.
for record in "$run/builder/record.txt" "$run/statements/record.txt" "$run/record.txt"; do
    [ -f "$record" ] || continue
    {
        echo "the testnet's errors:"
        grep ' ERROR ' "$run/testnet.log" || echo "  none"
    } | tee -a "$record"
done
echo "run: $run"
exit "$status"
