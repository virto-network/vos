#!/bin/sh
# x86-device-io.sh <vos-phone> <before> <device> <out.jsonl>: the device
# io-hash's x86 bench at the pin (blowup 4, 47 queries, PoW 16,
# Blake2s-M31): the lean kernel ending with BLAKE2b (<before>, 7.17's
# kernels) and the device kernel ending with H_io (<device>: the test
# actor's `auth`, or the spike's `auth_p2`, as `p2.kernel`), interleaved in
# three rounds on four P-cores; each on 4 P + 4 E cores under
# `--threads auto`; the device kernel at the other candidates. 5 reps after
# a warm-up, under the owner's memory cap, one run at a time.
set -e
phone=$1; before=$2; device=$3; out=$4
cap="systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0 nice -n 10"
pin=p2/2:47:16/b2sm31
cell() { name=$1; cpus=$2; kernels=$3; shift 3
  echo "# $name $(date -Is) $(uptime)"
  $cap taskset -c $cpus "$phone" device --kernels $kernels "$@" 2>/dev/null | grep device_cell | sed "s/^/$name /"
}
set8=1,3,6,8,12,13,14,15
{
  for round in 1 2 3; do
    cell before$round 1,3,6,8 "$before" --threads 4 --reps 5 --warmups 1 --cells $pin
    cell device$round 1,3,6,8 "$device" --threads 4 --reps 5 --warmups 1 --cells $pin
  done
  cell before-auto8 $set8 "$before" --threads auto --reps 5 --warmups 1 --cells $pin
  cell device-auto8 $set8 "$device" --threads auto --reps 5 --warmups 1 --cells $pin
  cell device-params 1,3,6,8 "$device" --threads 4 --reps 5 --warmups 1 \
    --cells p2/1:86:20/b2sm31,p2/2:43:20/b2sm31,p2/3:29:20/b2sm31
  echo "# end $(date -Is) $(uptime)"
} > "$out" 2>&1
