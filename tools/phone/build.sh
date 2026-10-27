#!/bin/sh
# build.sh [<out-dir>]: the phone bench's two Android binaries, arm64-v8a,
# against the NDK s4's Android client builds with (28.2), mimalloc as the
# allocator:
#
# - `vos-phone-timing`: the device library's proofs timed and verified,
#   masks from the operating system;
# - `vos-phone-seeded`: the same with seeded masks and the x86 proofs'
#   SHA-256 compiled in, every proof checked byte for byte.
#
# The references come from an x86 run of the seeded build over the same
# cells. Needs cargo-ndk, the rustup target aarch64-linux-android and
# ANDROID_NDK_HOME (default /opt/android-sdk/ndk/28.2.13676358).
set -e
root=$(cd "$(dirname "$0")/../.." && pwd)
out=${1:-$root/target/phone}
export ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-/opt/android-sdk/ndk/28.2.13676358}
cd "$root"
mkdir -p "$out"
cargo build --release -p vos-phone --features seeded
references=$(target/release/vos-phone run --reps 1 --grind 0 2>/dev/null \
  | sed -n 's/.*"cell":"\([^"]*\)".*"proof_sha256":"\([0-9a-f]*\)".*/\1=\2/p' | paste -sd, -)
echo "references: $references"
android() {
  cargo ndk -t arm64-v8a -P 30 build --release -p vos-phone "$@"
}
strip=$(find "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" -path '*/bin/llvm-strip' -print -quit)
android --features mimalloc
"$strip" -o "$out/vos-phone-timing" target/aarch64-linux-android/release/vos-phone
VOS_PHONE_REFERENCES=$references android --features mimalloc,seeded
"$strip" -o "$out/vos-phone-seeded" target/aarch64-linux-android/release/vos-phone
echo "$references" | tr , '\n' > "$out/x86-references.txt"
(cd "$out" && sha256sum vos-phone-timing vos-phone-seeded > vos-phone.sha256 && cat vos-phone.sha256)
