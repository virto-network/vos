#!/bin/sh
# p6.sh <vos-phone-timing> <vos-phone-timing-a720> <before> <lean> <out.txt>:
# session P6 on the gate phone (slice 7's 7.17c), over adb: the cheap
# margin before the CPU split, each lever against the baseline at the pin
# (blowup 4, 47 queries, PoW 16, Blake2s-M31, masked).
#
# - <vos-phone-timing>: `tools/phone/build.sh`'s timing build (mimalloc);
#   <vos-phone-timing-a720>: the same built with `-C target-cpu=cortex-a720`;
# - <before>: the device kernel as main has it (2,860 steps, the CPU at
#   2^12 rows), `p2.kernel` and `p2.input`; <lean>: the kernel moving
#   words (1,722 steps, the CPU at its floor 2^11), the same input.
#
# Three rounds, each interleaving seven runs of 5 proofs after a warm-up,
# every proof verified on the phone:
# 1. base:    <before>, automatic threads (the four big cores, pinned);
# 2. lean:    <lean>, automatic threads;
# 3. lean8:   <lean>, the eight cores pinned, big first (`--cores
#             4,5,6,7,0,1,2,3`): the little cores taking work by stealing;
# 4. lean6:   <lean>, the big cores and two little ones pinned;
# 5. purge:   <lean>, automatic threads, mimalloc never purging
#             (`MIMALLOC_PURGE_DELAY=-1`): no page refaulted between phases;
# 6. a720:    <lean> on the cortex-a720 build, automatic threads;
# 7. h256:    <lean>, automatic threads, `h = 256` (`p2/2:47:16:8`): a
#             proposal, not format 43 (its rule asks `h` twice the 149 rows
#             a column reveals); measured to decide it;
# then three cold runs of the lean kernel as an app proves it (`vos-phone
# kernel`: a fresh process, its prover and pool made, the program computed,
# one proof). The battery, the temperature, the free memory and both
# clusters' governors before and after each run, waiting (up to an hour)
# before a run at or above 35.0 °C or below 50%; the kills the event log
# records since the start. Removes what it pushed.
set -e
phone=$1; a720=$2; before=$3; lean=$4; out=$5
dir=/data/local/tmp/s7-p6
pin=p2/2:47:16/b2sm31
a="adb -s ${P6_SERIAL:-7689b5a9}"
cell="--cells $pin --reps 5 --warmups 1"
state() {
  $a shell "dumpsys battery | grep -E '^  (level|temperature):'; grep MemAvailable /proc/meminfo; cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor /sys/devices/system/cpu/cpu7/cpufreq/scaling_governor | paste -sd ' '"
}
ready() {
  level=$($a shell dumpsys battery | sed -n 's/^  level: //p' | tr -d '\r')
  temp=$($a shell dumpsys battery | sed -n 's/^  temperature: //p' | tr -d '\r')
  [ "$level" -ge 50 ] && [ "$temp" -lt 350 ]
}
run() {
  echo "== $1"; date; state
  waited=0
  until ready; do
    [ $waited -ge 30 ] && { echo "not ready after an hour: stopping"; exit 1; }
    echo "not ready: waiting"; sleep 120; waited=$((waited + 1)); state
  done
  shift
  $a shell "cd $dir && $*" || echo "exit=$?"
  state
}
# Whatever ends the session, what it pushed is removed.
cleanup() {
  $a shell rm -rf $dir
  $a shell ls $dir 2>&1 || true
}
trap cleanup EXIT
{
  $a shell getprop ro.product.model; $a shell getprop ro.build.fingerprint; $a shell uptime
  start=$($a shell "date '+%m-%d %H:%M:%S.000'" | tr -d '\r')
  $a shell mkdir -p $dir/before $dir/lean
  $a push "$phone" $dir/vos-phone >/dev/null
  $a push "$a720" $dir/vos-phone-a720 >/dev/null
  $a push "$before"/p2.kernel "$before"/p2.input $dir/before/ >/dev/null
  $a push "$lean"/p2.kernel "$lean"/p2.input $dir/lean/ >/dev/null
  $a shell chmod 755 $dir/vos-phone $dir/vos-phone-a720
  $a shell sha256sum $dir/vos-phone $dir/vos-phone-a720 $dir/before/p2.kernel $dir/lean/p2.kernel
  for n in 1 2 3; do
    run "round $n, base" ./vos-phone device --kernels before $cell
    run "round $n, lean" ./vos-phone device --kernels lean $cell
    run "round $n, lean8" ./vos-phone device --kernels lean $cell --cores 4,5,6,7,0,1,2,3
    run "round $n, lean6" ./vos-phone device --kernels lean $cell --cores 4,5,6,7,0,1
    run "round $n, purge" MIMALLOC_PURGE_DELAY=-1 ./vos-phone device --kernels lean $cell
    run "round $n, a720" ./vos-phone-a720 device --kernels lean $cell
    run "round $n, h256" ./vos-phone device --kernels lean --cells p2/2:47:16:8/b2sm31 \
      --reps 5 --warmups 1
    sleep 60
  done
  for n in 1 2 3; do
    run "cold $n, lean" ./vos-phone kernel --kernel lean/p2.kernel --input lean/p2.input --out lean/$n.proof
  done
  echo "== kills since $start"
  $a shell "logcat -d -b events -t '$start' | grep -E 'am_kill|am_low_memory|lmk' || true"
  $a shell "logcat -d -b main -t '$start' | grep -iE 'lowmemorykiller|lmkd.*kill' || true"
  date
} > "$out" 2>&1
