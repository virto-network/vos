#!/bin/sh
# x86.sh <harness> <out.jsonl>: 7.0a's x86 matrix. Both shapes at the device
# candidates nearest today's AIR (blowup 2 with 86 and 87 queries, blowup 4
# with 43) and the kit's configuration (blowup 4, 38 queries: the phone run's
# continuity), plain and under the proxy (`masked0`: every column one log
# size up, as the plan states it; `masked12`/`masked11`: padded to the floor
# masking (c) needs at those parameters first). 4 threads pinned to four
# P-cores, 8 threads over the six P-cores' twelve; 5 reps; under the
# owner's memory cap, one run at a time.
set -e
harness=$1; out=$2
cd "$(dirname "$0")/.."
elf=guest/target/riscv64em-vos/release/device-statements.elf
cells="built/1:86:20/plain,floor/1:86:20/plain,built/1:86:20/masked0,floor/1:86:20/masked0,\
built/1:86:20/masked12,floor/1:86:20/masked12,\
built/2:43:20/plain,floor/2:43:20/plain,built/2:43:20/masked0,floor/2:43:20/masked0,\
built/2:43:20/masked11,floor/2:43:20/masked11,\
built/2:38:20/plain,floor/2:38:20/plain"
bytes="built/1:87:20/plain,floor/1:87:20/plain,built/1:87:20/masked12,floor/1:87:20/masked12"
cap="systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0 nice -n 10"
{
  echo "# $(date -Is) $(uptime)"
  $cap taskset -c 1,3,6,8 "$harness" run --elf $elf --input data/auth.input --cells "$cells" --threads 4 --reps 5 --pause 2
  echo "# $(date -Is) $(uptime)"
  $cap taskset -c 0-11 "$harness" run --elf $elf --input data/auth.input --cells "$cells" --threads 8 --reps 5 --pause 2
  echo "# $(date -Is) $(uptime)"
  $cap taskset -c 1,3,6,8 "$harness" run --elf $elf --input data/auth.input --cells "$bytes" --threads 4 --reps 1 --pause 0
  for threads in 4 8; do
    $cap taskset -c 0-11 env RAYON_NUM_THREADS=$threads "$harness" grind --bits 20 --n 128
    $cap taskset -c 0-11 env RAYON_NUM_THREADS=$threads "$harness" grind --bits 16 --n 128
  done
  echo "# $(date -Is) $(uptime)"
} > "$out" 2>&1
