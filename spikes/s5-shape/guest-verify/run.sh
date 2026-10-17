#!/bin/sh
# run.sh [--tamper] [--profile] <proof.postcard>... : the guest verifier on
# the JAM-only host, and natively, for each proof. Each proof's commitment
# is beside it: <name>.commitment.postcard, or <stem>-seg0.commitment.postcard
# for a chain's segment <stem>-seg<i>.postcard.
here=$(cd "$(dirname "$0")" && pwd)
H=$here/harness/target/release/harness
E=$here/guest/target/riscv64em-vos-atomic/release/verify.elf
args=""
for p in "$@"; do
  case "$p" in --*) args="$args $p"; continue;; esac
  c="${p%.postcard}.commitment.postcard"
  [ -f "$c" ] || c="$(dirname "$p")/$(basename "$p" .postcard | sed 's/-seg[0-9]*$//')-seg0.commitment.postcard"
  args="$args $p:$c"
done
exec systemd-run --user --scope -q -p MemoryMax=14G -p MemorySwapMax=0 nice -n 10 "$H" "$E" $args
