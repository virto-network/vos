#!/bin/sh
# group.sh <vos-phone> <out.txt> [rounds]: the device group on the gate
# phone over adb (`light-node.md` §3.4): `vos-phone group` on groups of 3
# and of 8 devices, each a light node's store on the phone, paired and then
# updated round after round (20 by default), the committer's commit, each
# device's processing of the candidate on a copy and its vote, and each
# device's confirmation timed; one `group` line a group size, with the
# state sizes. PG6's limit for a candidate on a copy is 200 ms.
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
phone=$1; out=$2; rounds=${3:-20}
host=$(mktemp -d "${TMPDIR:-/var/tmp}/group.XXXXXX")
dir=/data/local/tmp/vos-group
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
  echo "== group: rounds"; date; state
  on_phone "./vos-phone group --dir stores --devices 3,8 --rounds $rounds"
  date; state
} 2>&1 | tee "$out"
[ "$(grep -c '"group":"rounds"' "$out")" -eq 2 ] || { echo "a group size did not run" >&2; exit 1; }
echo "group: every size ran"
