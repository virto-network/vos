#!/bin/sh
# x86-params.sh <vos-phone> <kernels> <out.jsonl>: 7.16's x86 matrix, the
# device cells of `tools/phone`: the auth statement over the Poseidon2 tree
# and over the vos-tree at every candidate on Blake2s-M31, 4 threads pinned
# to four P-cores, 5 reps after a warm-up; the Poseidon2 statement's
# candidates again on 8 threads over the six P-cores' twelve; and on
# Blake2b-256, one rep a candidate (about ten times slower). Under the
# owner's memory cap, one run at a time; the load recorded between passes.
set -e
phone=$1; kernels=$2; out=$3
cap="systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0 nice -n 10"
p2="p2/1:86:20/b2sm31,p2/1:87:20/b2sm31,p2/2:43:20/b2sm31,p2/2:47:16/b2sm31,p2/3:29:20/b2sm31"
b2b="p2/1:86:20/b2b,p2/2:43:20/b2b,p2/2:47:16/b2b,p2/3:29:20/b2b"
{
  echo "# $(date -Is) $(uptime)"
  $cap taskset -c 1,3,6,8 "$phone" device --kernels "$kernels" --threads 4 --reps 5 --warmups 1
  echo "# $(date -Is) $(uptime)"
  $cap taskset -c 0-11 "$phone" device --kernels "$kernels" --threads 8 --reps 5 --warmups 1 --cells "$p2"
  echo "# $(date -Is) $(uptime)"
  $cap taskset -c 1,3,6,8 "$phone" device --kernels "$kernels" --threads 4 --reps 1 --warmups 0 --cells "$b2b"
  echo "# $(date -Is) $(uptime)"
} > "$out" 2>&1
