#!/bin/sh
# p4.sh <vos-phone-timing> <kernels> <out.txt>: session P4 on the gate phone
# (slice 7's 7.16), over adb: the device cells pushed under
# /data/local/tmp/vos-p4, then
# - three rounds of the Poseidon2 statement at every candidate on
#   Blake2s-M31, automatic threads, 5 reps after a warm-up, 60 s apart;
# - one round of the same on the four big cores (`taskset f0`);
# - one round of the BLAKE2b statement at every candidate;
# - one Blake2b-256 cell, one rep;
# the battery and the temperature before and after each, waiting (up to an hour)
# before a round at or above 35.0 °C or below 50%. Removes what it pushed.
set -e
phone=$1; kernels=$2; out=$3
dir=/data/local/tmp/vos-p4
p2="p2/1:86:20/b2sm31,p2/1:87:20/b2sm31,p2/2:43:20/b2sm31,p2/2:47:16/b2sm31,p2/3:29:20/b2sm31"
b2="b2/1:86:20/b2sm31,b2/2:43:20/b2sm31,b2/2:47:16/b2sm31,b2/3:29:20/b2sm31"
a="adb -s 7689b5a9"
battery() {
  $a shell dumpsys battery | grep -E '^  (level|temperature):'
}
ready() {
  level=$($a shell dumpsys battery | sed -n 's/^  level: //p' | tr -d '\r')
  temp=$($a shell dumpsys battery | sed -n 's/^  temperature: //p' | tr -d '\r')
  [ "$level" -ge 50 ] && [ "$temp" -lt 350 ]
}
round() {
  echo "== $1"; date; battery
  waited=0
  until ready; do
    [ $waited -ge 30 ] && { echo "not ready after an hour: stopping"; $a shell rm -rf $dir; exit 1; }
    echo "not ready: waiting"; sleep 120; waited=$((waited + 1))
  done
  shift
  $a shell "cd $dir && $*" || echo "exit=$?"
  battery
}
{
  $a shell getprop ro.product.model; $a shell getprop ro.build.fingerprint; $a shell uptime
  $a shell mkdir -p $dir/kernels
  $a push "$phone" $dir/vos-phone >/dev/null
  $a push "$kernels"/p2.kernel "$kernels"/p2.input "$kernels"/b2.kernel "$kernels"/b2.input $dir/kernels/ >/dev/null
  $a shell chmod 755 $dir/vos-phone
  for n in 1 2 3; do
    round "round $n, p2, automatic threads" ./vos-phone device --cells $p2 --reps 5 --warmups 1
    sleep 60
  done
  round "p2, the four big cores" taskset f0 ./vos-phone device --cells $p2 --reps 5 --warmups 1 --threads 4
  sleep 60
  round "b2, automatic threads" ./vos-phone device --cells $b2 --reps 5 --warmups 1
  sleep 60
  round "p2 on Blake2b-256" ./vos-phone device --cells p2/2:43:20/b2b --reps 1 --warmups 0
  $a shell rm -rf $dir
  $a shell ls $dir 2>&1 || true
  date
} > "$out" 2>&1
