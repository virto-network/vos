#!/bin/sh
# sync.sh <vos-phone> <out.txt> [rounds]: sealed sync on the gate phone over
# adb (`light-node.md` §3.6), PG6's 1 MiB catch-up, the device's part:
# `vos-phone sync` pairs two devices, each a light node's store on the
# phone, writes a mebibyte of titles on one in small operations (1,000
# bytes) and in the largest a call takes, pushes it sealed to a stand-in
# agent in the process, and catches it up on the other: every envelope
# opened and its node applied. One `sync` line a shape, the catch-up's p50
# and p95 over the rounds (3 by default), each a fresh scope. PG6's limit
# for the catch-up over Tor is 20 s at p50, of which this is the phone's
# part; the round trips are the host's and Tor's (S8-P5, S8-P6).
#
# Battery, temperature and free memory are recorded before and after; what
# was pushed is removed at the end.
#
# <vos-phone> is `tools/phone/build.sh`'s `vos-phone-timing`, built after
# `just build-programs build-test-actors`; the phone is adb's LIGHT_SERIAL
# (the gate phone's by default). With LIGHT_LOCAL=1 the "phone" is this
# host and <vos-phone> an x86 build (`cargo build --release -p
# vos-phone`): the script's dry run.
set -e
phone=$1; out=$2; rounds=${3:-3}
host=$(mktemp -d "${TMPDIR:-/var/tmp}/sync.XXXXXX")
dir=/data/local/tmp/vos-sync
a="adb -s ${LIGHT_SERIAL:-7689b5a9}"
if [ "${LIGHT_LOCAL:-0}" = 1 ]; then dir=$host/phone; fi
cleanup() {
  if [ "${LIGHT_LOCAL:-0}" != 1 ]; then $a shell "rm -rf $dir" || true; fi
  rm -rf "$host"
}
trap cleanup EXIT
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
  echo "== sync: catch-up"; date; state
  on_phone "./vos-phone sync --dir stores --rounds $rounds"
  date; state
} 2>&1 | tee "$out"
[ "$(grep -c '"sync":"catch_up"' "$out")" -eq 2 ] || { echo "a shape did not run" >&2; exit 1; }
echo "sync: every shape ran"
