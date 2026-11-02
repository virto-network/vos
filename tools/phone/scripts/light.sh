#!/bin/sh
# light.sh <vos-phone> <out.txt> [rounds]: the light node's gate on the gate
# phone over adb (`light-node.md` §2.1).
#
# 1. A local actor installed from the release artifacts the binary embeds
#    and called: `vos-phone light` on a new store, 500 calls timed, then
#    its value read back; then again on the same store, which reopens with
#    the counter installed and its calls applied.
# 2. A process killed mid-operation leaves the store consistent: for each
#    round (10 by default), `vos-phone light` calling in a loop on one store
#    is killed (SIGKILL) a random 50-800 ms after it starts, and `vos-phone
#    light --check` must find the store one prefix of the operations, each
#    whole (`"consistent":true`, exit 0).
#
# Battery, temperature and free memory are recorded before each part; what
# was pushed is removed at the end. Exits 0 when every step passed.
#
# <vos-phone> is `tools/phone/build.sh`'s `vos-phone-timing`, built after
# `just build-agent build-test-actors` (its build script embeds the
# artifacts from those ELFs); the phone is adb's LIGHT_SERIAL (the gate
# phone's by default). With LIGHT_LOCAL=1 the "phone" is this host and
# <vos-phone> an x86 build (`cargo build --release -p vos-phone`): the
# script's dry run.
set -e
phone=$1; out=$2; rounds=${3:-10}
host=$(mktemp -d "${TMPDIR:-/var/tmp}/light.XXXXXX")
dir=/data/local/tmp/vos-light
a="adb -s ${LIGHT_SERIAL:-7689b5a9}"
if [ "${LIGHT_LOCAL:-0}" = 1 ]; then dir=$host/phone; fi
on_phone() {
  if [ "${LIGHT_LOCAL:-0}" = 1 ]; then (cd "$dir" && sh -c "$*"); else $a shell "cd $dir && $*"; fi
}
state() {
  if [ "${LIGHT_LOCAL:-0}" = 1 ]; then grep MemAvailable /proc/meminfo; return; fi
  $a shell "dumpsys battery | grep -E '^  (level|temperature):'; grep MemAvailable /proc/meminfo"
}
if [ "${LIGHT_LOCAL:-0}" = 1 ]; then
  mkdir -p "$dir"; cp "$phone" "$dir/vos-phone"
else
  $a shell "rm -rf $dir && mkdir -p $dir"
  $a push "$phone" "$dir/vos-phone" >/dev/null
fi
on_phone "chmod +x vos-phone"
{
  echo "== light: install and calls"; date; state
  on_phone "./vos-phone light --store calls --calls 500"
  echo "== light: reopened"
  on_phone "./vos-phone light --store calls --calls 500"
  echo "== light: kills, $rounds rounds"; date; state
  round=1
  while [ "$round" -le "$rounds" ]; do
    wait_ms=$(( ($(od -An -N2 -tu2 /dev/urandom) % 750) + 50 ))
    secs=$(printf '0.%03d' "$wait_ms")
    on_phone "./vos-phone light --store kills --calls 100000000 > /dev/null 2>&1 & pid=\$!; sleep $secs; kill -9 \$pid; wait \$pid 2>/dev/null; true"
    echo "round $round, killed after ${wait_ms} ms:"
    on_phone "./vos-phone light --store kills --check"
    round=$((round + 1))
  done
  date; state
} 2>&1 | tee "$out"
grep -q '"consistent":false' "$out" && { echo "a store was not consistent" >&2; exit 1; }
[ "$(grep -c '"light":"check"' "$out")" -eq "$rounds" ] || { echo "a check did not run" >&2; exit 1; }
if [ "${LIGHT_LOCAL:-0}" != 1 ]; then $a shell "rm -rf $dir"; fi
rm -rf "$host"
echo "light: every step passed"
