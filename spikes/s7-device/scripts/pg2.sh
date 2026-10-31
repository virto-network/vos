#!/bin/sh
# pg2.sh <vos-phone> <out.txt> [rounds]: phone gate PG2's acceptance at a
# space's ingress (slice 7's 7.20), the gate phone over adb.
#
# The host runs one node of a founded space (`cargo run --release -p
# vos-node --example device_ingress`): the credential actor and the device
# actor installed, a member enrolled. For each round (3 by default) it
# writes the device kernel's witness input for a sign-in to the device
# actor's `login`, good for 110 s by the node's clock; the phone proves it
# with `vos-phone kernel` (the device library's `DeviceProgram::auth` and
# `Prover::prove_kernel`, format 43, automatic threads), verifies it there
# and writes its bytes; the host pulls them and sends them to the node's
# ingress, which must run the call as the member's pseudonym. Battery,
# temperature and free memory are recorded before each round; what was
# pushed is removed at the end. Exits 0 when every round ran.
#
# <vos-phone> is `tools/phone/build.sh`'s `vos-phone-timing`; the phone
# is adb's PG2_SERIAL (the gate phone's by default). With
# PG2_LOCAL=1 the "phone" is this host and <vos-phone> an x86 build
# (`cargo build --release -p vos-phone`): the script's dry run.
set -e
phone=$1; out=$2; rounds=${3:-3}
root=$(cd "$(dirname "$0")/../../.." && pwd)
host=$(mktemp -d "${TMPDIR:-/var/tmp}/pg2.XXXXXX")
dir=/data/local/tmp/s7-pg2
a="adb -s ${PG2_SERIAL:-7689b5a9}"
if [ "${PG2_LOCAL:-0}" = 1 ]; then dir=$host/phone; fi
on_phone() {
  if [ "${PG2_LOCAL:-0}" = 1 ]; then (cd "$dir" && sh -c "$*"); else $a shell "cd $dir && $*"; fi
}
push() {
  if [ "${PG2_LOCAL:-0}" = 1 ]; then cp "$1" "$dir/$2"; else $a push "$1" "$dir/$2" >/dev/null; fi
}
pull() {
  if [ "${PG2_LOCAL:-0}" = 1 ]; then cp "$dir/$1" "$2"; else $a pull "$dir/$1" "$2" >/dev/null; fi
}
state() {
  if [ "${PG2_LOCAL:-0}" = 1 ]; then uptime; grep MemAvailable /proc/meminfo; return; fi
  $a shell "dumpsys battery | grep -E '^  (level|temperature):'; grep MemAvailable /proc/meminfo"
}
# Whatever ends the run, the witness inputs and proofs pushed are removed.
cleanup() {
  if [ "${PG2_LOCAL:-0}" = 1 ]; then rm -rf "$dir"; else $a shell rm -rf $dir; fi
}
trap cleanup EXIT
# Waits up to two minutes for the host's file $1.
wait_file() {
  waited=0
  until [ -s "$1" ]; do
    [ $waited -ge 480 ] && { echo "no $1 after two minutes"; return 1; }
    sleep 0.25; waited=$((waited + 1))
  done
}
{
  cd "$root"
  just build-agent build-credentials build-test-actors >/dev/null
  cargo build --release -p vos-node --example device_ingress
  if [ "${PG2_LOCAL:-0}" = 1 ]; then
    mkdir -p "$dir"; uname -a
  else
    $a shell getprop ro.product.model; $a shell getprop ro.build.fingerprint
    $a shell mkdir -p $dir
  fi
  target/release/examples/device_ingress "$host" --rounds "$rounds" --wait 110 \
    > "$host/rounds.jsonl" 2> "$host/host.log" &
  node=$!
  wait_file "$host/auth.kernel"
  push "$phone" vos-phone
  push "$host/auth.kernel" auth.kernel
  on_phone chmod 755 vos-phone
  on_phone sha256sum vos-phone auth.kernel
  n=1
  while [ $n -le "$rounds" ]; do
    echo "== round $n"; date; state
    wait_file "$host/$n.input"
    push "$host/$n.input" "$n.input"
    on_phone ./vos-phone kernel --kernel auth.kernel --input "$n.input" --out "$n.proof" \
      || echo "the phone's prove: exit=$?"
    pull "$n.proof" "$host/$n.part" && mv "$host/$n.part" "$host/$n.proof"
    n=$((n + 1))
  done
  status=0
  wait $node || status=$?
  echo "== the node's answers"
  cat "$host/rounds.jsonl"
  date
  echo "exit=$status"
} > "$out" 2>&1
grep -q '^exit=0$' "$out"
