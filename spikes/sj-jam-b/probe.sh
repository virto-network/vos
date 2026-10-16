#!/usr/bin/env bash
# The probe on a local PolkaJam testnet. Commands:
#   probe.sh build                    build the guest and the tool, link the blob
#   probe.sh testnet <run-dir>        start polkajam-testnet there
#   probe.sh create                   create the service (prints its id)
#   probe.sh item <service> <payload> [jamt item options...]
#   probe.sh get <service> <key>      a storage value, in full, as hex (RPC)
#   probe.sh provide <service>        provide the preimage `S` solicits
#   probe.sh compare <service> <key>  PolkaJam's records beside VOS's
#   probe.sh local <payload>          refine on VOS's JAM-only host
# POLKAJAM names the directory holding the PolkaJam binaries. POLKAVM_BACKEND
# picks the testnet's PVM backend, `interpreter` (the default) or `compiler`.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
POLKAJAM="${POLKAJAM:-$HOME/.cache/vos/polkajam/nightly-2026-10-13/polkajam-nightly-2026-10-13-linux-x86_64}"
RPC="${RPC:-http://localhost:19800}"
backend="${POLKAVM_BACKEND:-interpreter}"
tool="$here/tool/target/release/sj-probe-tool"
blob="$here/sj-probe.jam"

rpc() {
    curl -s -m 20 -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$RPC"
}

field() {
    python3 -I -c "import json,sys; r=json.load(sys.stdin)['result']; print(r$1 if r is not None else '')"
}

get() {
    local head key value
    head="$(rpc bestBlock '[]' | field "['header_hash']")"
    key="$(printf '%s' "$2" | base64 -w0)"
    value="$(rpc serviceValue "[\"$head\",$1,\"$key\"]" | field '')"
    [ -n "$value" ] || { echo "no value for $2" >&2; return 1; }
    printf '%s' "$value" | base64 -d | od -An -v -tx1 | tr -d ' \n'
    echo
}

case "${1:-}" in
build)
    (cd "$here/guest" && cargo build --release --target riscv64em-vos.json)
    (cd "$here/tool" && cargo build --release)
    "$tool" link "$here/guest/target/riscv64em-vos/release/sj-probe.elf" "$blob" vos-sj-probe
    ;;
testnet)
    mkdir -p "$2" && cd "$2"
    PATH="$POLKAJAM:$PATH" POLKAVM_BACKEND="$backend" setsid \
        systemd-run --user --scope -q -p MemoryMax=24G -p MemorySwapMax=0 \
        "$POLKAJAM/polkajam-testnet" >testnet.log 2>&1 &
    echo "$!" >testnet.pid
    echo "testnet ($backend) process group $(cat testnet.pid); stop with: kill -TERM -$(cat testnet.pid)"
    ;;
create) "$POLKAJAM/jamt" create-service --raw "$blob" 1000000000 ;;
item)
    service="$2"; payload="$3"; shift 3
    "$POLKAJAM/jamt" item "$@" "$service" "$payload"
    ;;
get) get "$2" "$3" ;;
provide)
    python3 -I -c 'import sys; sys.stdout.buffer.write(bytes((i * 37 + 11) & 0xff for i in range(300)))' \
        >"$here/probe-preimage.bin"
    "$POLKAJAM/jamt" provide "$(printf '%08x' "$2")" "$here/probe-preimage.bin"
    ;;
compare) "$tool" compare "$blob" "$(get "$2" "$3")" ;;
local) "$tool" local "$blob" "$2" ;;
*) sed -n '2,12p' "$0"; exit 1 ;;
esac
