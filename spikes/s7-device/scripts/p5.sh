#!/bin/sh
# p5.sh <vos-phone-timing> <before> <device> <out.txt>: session P5 on the gate
# phone (slice 7's 7.17b), over adb: the device io-hash's kernel against
# 7.17's lean kernel (BLAKE2b io-hash) at the pin (blowup 4, 47 queries,
# PoW 16, Blake2s-M31), pushed under /data/local/tmp/s7-p5, then
# - three rounds, each interleaving: before and device under automatic
#   threads, before and device on the four big cores (`taskset f0`,
#   `--threads 4`), 5 reps after a warm-up;
# - one round of the device kernel at blowup 2 (86 queries, PoW 20) and
#   blowup 4 at PoW 20 (43 queries), automatic threads;
# the battery, the temperature and the free memory before and after each,
# waiting (up to an hour) before a run at or above 35.0 °C or below 50%;
# the kills the event log records since the start. Removes what it pushed.
set -e
phone=$1; before=$2; device=$3; out=$4
dir=/data/local/tmp/s7-p5
pin=p2/2:47:16/b2sm31
a="adb -s 7689b5a9"
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
    [ $waited -ge 30 ] && { echo "not ready after an hour: stopping"; $a shell rm -rf $dir; exit 1; }
    echo "not ready: waiting"; sleep 120; waited=$((waited + 1)); state
  done
  shift
  $a shell "cd $dir && $*" || echo "exit=$?"
  state
}
{
  $a shell getprop ro.product.model; $a shell getprop ro.build.fingerprint; $a shell uptime
  start=$($a shell "date '+%m-%d %H:%M:%S.000'" | tr -d '\r')
  $a shell mkdir -p $dir/before $dir/device
  $a push "$phone" $dir/vos-phone >/dev/null
  $a push "$before"/p2.kernel "$before"/p2.input $dir/before/ >/dev/null
  $a push "$device"/p2.kernel "$device"/p2.input $dir/device/ >/dev/null
  $a shell chmod 755 $dir/vos-phone
  $a shell sha256sum $dir/vos-phone $dir/before/p2.kernel $dir/device/p2.kernel
  for n in 1 2 3; do
    run "round $n, before, auto" ./vos-phone device --kernels before --cells $pin --reps 5 --warmups 1
    run "round $n, device, auto" ./vos-phone device --kernels device --cells $pin --reps 5 --warmups 1
    run "round $n, before, big" taskset f0 ./vos-phone device --kernels before --cells $pin --reps 5 --warmups 1 --threads 4
    run "round $n, device, big" taskset f0 ./vos-phone device --kernels device --cells $pin --reps 5 --warmups 1 --threads 4
    sleep 60
  done
  run "device, other parameters, auto" ./vos-phone device --kernels device \
    --cells p2/1:86:20/b2sm31,p2/2:43:20/b2sm31 --reps 5 --warmups 1
  echo "== kills since $start"
  $a shell "logcat -d -b events -t '$start' | grep -E 'am_kill|am_low_memory|lmk' || true"
  $a shell "logcat -d -b main -t '$start' | grep -iE 'lowmemorykiller|lmkd.*kill' || true"
  $a shell rm -rf $dir
  $a shell ls $dir 2>&1 || true
  date
} > "$out" 2>&1
