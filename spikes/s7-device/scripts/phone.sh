#!/bin/sh
# phone.sh <musl-aarch64-include> [<out-dir>]: session P1's two phone
# binaries, static aarch64-unknown-linux-musl, mimalloc as the allocator:
#
# - `s7-phone-timing`: the cells timed, proofs verified, nothing compared;
# - `s7-phone-seeded`: the same with the x86 proofs' SHA-256 compiled in
#   (`seeded-masks`), every proof checked byte for byte.
#
# The x86 references come from the glibc build of the same harness, run once
# over the same cells. Needs the guest ELF built and `gen` run (both
# embedded), the rustup target aarch64-unknown-linux-musl, clang, llvm-ar,
# llvm-strip, and musl's aarch64 headers for mimalloc's C (musl 1.2.5's
# `include/` with its `bits/` for aarch64, as slice 5's kit built them).
set -e
include=$1
spike=$(cd "$(dirname "$0")/.." && pwd)
out=${2:-$spike/phone-dist}
copy=$("$spike/scripts/tree.sh")
mkdir -p "$copy/guest/target/riscv64em-vos/release" "$copy/data" "$out"
cp "$spike/guest/target/riscv64em-vos/release/device-statements.elf" "$copy/guest/target/riscv64em-vos/release/"
cp "$spike/data/auth.input" "$spike/data/auth.expected" "$copy/data/"
cd "$copy/harness"
cargo build --release --features phone --target-dir target-phone
references=$(target-phone/release/s7-device run --reps 1 --pause 0 --grind 0 --threads 8 2>/dev/null \
  | sed -n 's/.*"cell":"\([^"]*\)".*"proof_sha256":"\([0-9a-f]*\)".*/\1=\2/p' | paste -sd, -)
echo "references: $references"
cross() {
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  CC_aarch64_unknown_linux_musl=clang AR_aarch64_unknown_linux_musl=llvm-ar \
  CFLAGS_aarch64_unknown_linux_musl="--target=aarch64-linux-musl -nostdlibinc -isystem $include" \
  RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target aarch64-unknown-linux-musl --target-dir target-phone "$@"
}
cross --features phone,mimalloc
llvm-strip -o "$out/s7-phone-timing" target-phone/aarch64-unknown-linux-musl/release/s7-device
S7_REFERENCES=$references cross --features phone,mimalloc,seeded-masks
llvm-strip -o "$out/s7-phone-seeded" target-phone/aarch64-unknown-linux-musl/release/s7-device
echo "$references" | tr , '\n' > "$out/x86-references.txt"
(cd "$out" && sha256sum s7-phone-timing s7-phone-seeded > s7-phone.sha256 && cat s7-phone.sha256)
