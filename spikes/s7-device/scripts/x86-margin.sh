#!/bin/sh
# x86-margin.sh <vos-phone-seeded> <vos-phone-seeded-mimalloc> <before> <lean>
# <out.jsonl>: the device kernel's cheap levers on x86 at the device format's
# (blowup 4, 47 queries, PoW 16, Blake2s-M31), the seeded builds (every proof's masks
# from one seed, so a lever that moves no byte gives the same proof):
# - three rounds interleaving, on four P-cores, 5 reps after a warm-up:
#   the baseline kernel (<before>) and the one moving words (<lean>),
#   glibc's allocator against mimalloc's, mimalloc never purging;
# - on four P-cores and four E-cores, the lean kernel: automatic threads
#   (both classes kept, unpinned), the eight pinned, the P-cores alone
#   pinned, the eight unpinned;
# - the query and PoW slope: 47 queries at PoW 16 against 63 and 31, and
#   43 at PoW 20;
# - three cold runs as an app proves (`vos-phone kernel`: a fresh process,
#   its prover and pool made, the program computed, one proof).
# x86-margin.sh h <vos-phone-seeded> <lean> <out.jsonl>: the mask height
# alone, `h = 512` (format 43's, `:9`) against 256 (45's, `:8`) on the lean
# kernel, three interleaved rounds on four P-cores, 5 reps after a warm-up.
# Under the owner's memory cap, one run at a time, the load recorded.
set -e
cap="systemd-run --user --scope -q -p MemoryMax=12G -p MemorySwapMax=0 nice -n 10"
if [ "$1" = h ]; then
  seeded=$2; lean=$3; out=$4
  {
    for round in 1 2 3; do
      for log_h in 9 8; do
        echo "# h$log_h-$round $(date -Is) $(uptime)"
        $cap taskset -c 1,3,6,8 "$seeded" device-cell p2/2:47:16:$log_h/b2sm31 --kernels "$lean" \
          --threads 4 --reps 5 --warmups 1 2>/dev/null | grep device_cell | sed "s/^/h$log_h-$round /"
      done
    done
    echo "# end $(date -Is) $(uptime)"
  } > "$out" 2>&1
  exit
fi
seeded=$1; mi=$2; before=$3; lean=$4; out=$5
pin=p2/2:47:16/b2sm31
p4=1,3,6,8; p4e4=1,3,6,8,12,13,14,15
# cell <name> <cpus> <VAR=value> <vos-phone> <kernels> <flags…>
cell() { name=$1; cpus=$2; environment=$3; phone=$4; kernels=$5; shift 5
  echo "# $name $(date -Is) $(uptime)"
  $cap env $environment taskset -c $cpus "$phone" device-cell $pin --kernels "$kernels" --reps 5 --warmups 1 "$@" \
    2>/dev/null | grep device_cell | sed "s/^/$name /"
}
{
  for round in 1 2 3; do
    cell before$round $p4 S7=1 "$seeded" "$before" --threads 4
    cell lean$round $p4 S7=1 "$seeded" "$lean" --threads 4
    cell mimalloc$round $p4 S7=1 "$mi" "$lean" --threads 4
    cell purge$round $p4 MIMALLOC_PURGE_DELAY=-1 "$mi" "$lean" --threads 4
  done
  for round in 1 2; do
    cell auto8-$round $p4e4 S7=1 "$seeded" "$lean" --threads auto
    cell pinned8-$round $p4e4 S7=1 "$seeded" "$lean" --cores $p4e4
    cell pinned4-$round $p4e4 S7=1 "$seeded" "$lean" --cores $p4
    cell unpinned8-$round $p4e4 S7=1 "$seeded" "$lean" --threads 8
  done
  for cells in p2/2:63:16/b2sm31 p2/2:31:16/b2sm31 p2/2:43:20/b2sm31 $pin; do
    echo "# $cells $(date -Is) $(uptime)"
    $cap taskset -c $p4 "$seeded" device-cell $cells --kernels "$lean" --threads 4 --reps 5 \
      --warmups 1 2>/dev/null | grep device_cell | sed "s/^/slope /"
  done
  for round in 1 2 3; do
    echo "# cold$round $(date -Is) $(uptime)"
    $cap taskset -c $p4 "$seeded" kernel --kernel "$lean/p2.kernel" --input "$lean/p2.input" \
      --out /dev/null --threads 4 | sed "s/^/cold$round /"
  done
  echo "# end $(date -Is) $(uptime)"
} > "$out" 2>&1
