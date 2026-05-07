#!/usr/bin/env bash
# zkpvm PGO build script — Phase 61 (commit TBD).
#
# Profile-guided optimization gives a measured 18% prove-time win at
# log14 MOBILE on the reference Intel Core Ultra 7 155H (median of 5
# trials: 1.31 s → 1.07 s).  Stacks on top of target-cpu=native +
# fat LTO (already enabled in .cargo/config.toml + Cargo.toml).
#
# Three-step process:
#   1. Build instrumented binary with `-Cprofile-generate`.
#   2. Run the bench training workload to collect profile data.
#   3. Rebuild with `-Cprofile-use` pointing at merged data.
#
# Output: a release binary at target/release/* optimised for the
# training workload's hot paths.  Subsequent prove() calls in
# downstream binaries linked against zkpvm pick up the optimisation
# automatically.
#
# Caveat: the optimised binary is tuned for the training workload
# shape (currently the Add-bench profile harness).  Real-world
# workloads with very different opcode mixes may see less gain.
# To retrain for a specific workload, replace the test selector in
# step 2 with one exercising that workload (e.g.,
# `--test prove_vos_actor -- profile_hash_bench`).
#
# Requires: rustup component llvm-tools-preview (auto-installed if
# missing).

set -euo pipefail

PROFDIR="${ZKPVM_PGO_PROFDIR:-/tmp/zkpvm-pgo-data}"
TOOLCHAIN_BIN="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | grep ^host | awk '{print $2}')/bin"
PROFDATA="$TOOLCHAIN_BIN/llvm-profdata"

if [[ ! -x "$PROFDATA" ]]; then
  echo ">>> Installing llvm-tools-preview..."
  rustup component add llvm-tools-preview
fi

mkdir -p "$PROFDIR"
rm -f "$PROFDIR"/*.profraw "$PROFDIR/merged.profdata"

echo "=== Step 1/3: Instrumented build ==="
RUSTFLAGS="-C target-cpu=native -Cprofile-generate=$PROFDIR" \
  cargo build -p zkpvm --features prover --release --tests

echo "=== Step 2a/3: Training run — synthetic Add bench (ALU-heavy) ==="
RUSTFLAGS="-C target-cpu=native -Cprofile-generate=$PROFDIR" \
  cargo test -p zkpvm --features prover --release --test bench_prove \
  -- profile_log14_mobile bench_prove_log10 bench_prove_log12 bench_prove_log14 \
  --nocapture --test-threads 1 \
  > /dev/null

echo "=== Step 2b/3: Training run — clerk-private-pay (ECALL + ledger) ==="
# Cover the tap-to-pay opcode mix so PGO inlining / branch hints
# tune the prover for real-world latency-sensitive flows, not just
# synthetic Add traces.  Falls back silently if the actor blob isn't
# available in the local checkout (common on contributor machines).
RUSTFLAGS="-C target-cpu=native -Cprofile-generate=$PROFDIR" \
  cargo test -p zkpvm --features prover --release --test prove_vos_actor \
  -- profile_clerk_private_pay_bench_mobile profile_clerk_private_pay_bench \
  --nocapture --test-threads 1 \
  > /dev/null \
  || echo ">>> WARNING: clerk-private-pay-bench training skipped (actor blob missing); PGO will be ALU-tuned only."
# Both MOBILE (fri_blowup=2) and STANDARD (fri_blowup=16) shapes are
# trained in this pass so PGO covers both PCS configs — without the
# STANDARD bench, prove() under production_pcs_config() regresses
# slightly post-PGO (Session 1.1 follow-up of the perf roadmap).

echo "=== Step 3/3: Merge profiles + final build ==="
"$PROFDATA" merge -o "$PROFDIR/merged.profdata" "$PROFDIR"/*.profraw
RUSTFLAGS="-C target-cpu=native -Cprofile-use=$PROFDIR/merged.profdata" \
  cargo build -p zkpvm --features prover --release

echo
echo "=== PGO build complete ==="
echo "Profile data: $PROFDIR/merged.profdata"
echo
echo "To bench the PGO build:"
echo "  RUSTFLAGS=\"-C target-cpu=native -Cprofile-use=$PROFDIR/merged.profdata\" \\"
echo "    cargo test -p zkpvm --features prover --release --test bench_prove \\"
echo "    -- profile_log14_mobile --nocapture --test-threads 1"
