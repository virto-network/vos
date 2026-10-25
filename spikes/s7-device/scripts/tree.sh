#!/bin/sh
# tree.sh [<tree>]: the patched copy of the repository the harness builds in.
#
# The spike's seams (`pvm-proof.patch`: the Blake2s stack routed, a format
# the process admits under the device number, the memory chip's floor seam)
# never enter the repository: the tree at HEAD is exported to <tree>
# (default `$TMPDIR/s7-device-tree`) once and patched there; each call then
# copies this spike's sources over the copy's, so a build there sees them.
# Prints the copy's spike directory.
set -e
spike=$(cd "$(dirname "$0")/.." && pwd)
repo=$(git -C "$spike" rev-parse --show-toplevel)
tree=${1:-${TMPDIR:-/tmp}/s7-device-tree}
if [ ! -f "$tree/.s7-patched" ]; then
  rm -rf "$tree"
  mkdir -p "$tree"
  git -C "$repo" archive HEAD | tar -x -C "$tree"
  (cd "$tree" && patch -s -p1 < "$spike/pvm-proof.patch")
  git -C "$repo" rev-parse HEAD > "$tree/.s7-patched"
fi
mkdir -p "$tree/spikes/s7-device"
for part in guest harness scripts; do
  rsync -a --checksum --exclude target --exclude 'target-*' "$spike/$part/" "$tree/spikes/s7-device/$part/"
done
echo "$tree/spikes/s7-device"
