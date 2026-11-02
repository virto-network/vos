#!/bin/sh
# p7.sh <old vos-phone-timing> <new vos-phone-timing> <lean> <bench> <out.txt>:
# two timing builds A/B on the gate phone, over adb (P7_SERIAL, the gate
# phone's by default): the mask height `h = 256` against 512 and Stwo's NEON
# Blake2s compress against the scalar one, each alone and together.
#
# - <old vos-phone-timing>: a timing build with the scalar Blake2s compress;
#   <new vos-phone-timing>: `tools/phone/build.sh`'s timing build (Stwo's
#   NEON compress16);
# - <lean>: the lean device kernel, `p2.kernel` and `p2.input`;
# - <bench>: Stwo's `blake2s_compress_bench` example for aarch64 Android.
#
# Three rounds, each interleaving four runs of 5 proofs after a warm-up,
# every proof verified on the phone, automatic threads:
# 1. A: the old build, `h = 512` (`p2/2:47:16:9`);
# 2. B: the old build, `h = 256` (`p2/2:47:16:8`);
# 3. C: the new build, `h = 512` (`p2/2:47:16:9`): NEON alone;
# 4. D: the new build, its default (`h = 256`);
# then the microbench single-threaded: the 16-way compress old against new
# on the prime core (cpu7) and on a little core (cpu0), and the Merkle
# layer on the prime core. The battery, the temperature, the free memory
# and both clusters' governors before and after each run, waiting (up to an
# hour) before a run at or above 35.0 °C or below 50%; the kills the event
# log records since the start. Removes what it pushed.
set -e
old=$1; new=$2; lean=$3; bench=$4; out=$5
dir=/data/local/tmp/s7-p7
cells="--reps 5 --warmups 1 --kernels lean"
a="adb -s ${P7_SERIAL:-7689b5a9}"
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
trap 'exit 130' INT TERM HUP
{
  $a shell getprop ro.product.model; $a shell getprop ro.build.fingerprint; $a shell uptime
  start=$($a shell "date '+%m-%d %H:%M:%S.000'" | tr -d '\r')
  $a shell mkdir -p $dir/lean
  $a push "$old" $dir/vos-phone-old >/dev/null
  $a push "$new" $dir/vos-phone >/dev/null
  $a push "$bench" $dir/blake2s_compress_bench >/dev/null
  $a push "$lean"/p2.kernel "$lean"/p2.input $dir/lean/ >/dev/null
  $a shell chmod 755 $dir/vos-phone-old $dir/vos-phone $dir/blake2s_compress_bench
  $a shell sha256sum $dir/vos-phone-old $dir/vos-phone $dir/blake2s_compress_bench $dir/lean/p2.kernel
  for n in 1 2 3; do
    run "round $n, A (old, h=512)" ./vos-phone-old device $cells --cells p2/2:47:16:9/b2sm31
    run "round $n, B (old, h=256)" ./vos-phone-old device $cells --cells p2/2:47:16:8/b2sm31
    run "round $n, C (new, h=512)" ./vos-phone device $cells --cells p2/2:47:16:9/b2sm31
    run "round $n, D (new, default)" ./vos-phone device $cells --cells p2/2:47:16/b2sm31
    sleep 30
  done
  run "bench, compress16, cpu7" taskset 80 ./blake2s_compress_bench both 16 32 7
  run "bench, compress16, cpu0" taskset 01 ./blake2s_compress_bench both 16 32 7
  run "bench, merkle, cpu7" taskset 80 ./blake2s_compress_bench merkle 16 32 7
  echo "== kills since $start"
  $a shell "logcat -d -b events -t '$start' | grep -E 'am_kill|am_low_memory|lmk' || true"
  $a shell "logcat -d -b main -t '$start' | grep -iE 'lowmemorykiller|lmkd.*kill' || true"
  date
} > "$out" 2>&1
