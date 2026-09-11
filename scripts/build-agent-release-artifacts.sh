#!/usr/bin/env bash
# Reproduce only the Agent-generation runtime and system-package templates.
set -euo pipefail

mode=${1:-all}
case "$mode" in
    all|runtime|system) ;;
    *) echo "usage: $0 [all|runtime|system]" >&2; exit 2 ;;
esac
repository_root=$(git rev-parse --show-toplevel)
provenance="$repository_root/support/production-artifacts.toml"
manifest_value() {
    local value
    value=$(sed -n "s/^$1 = \"\([^\"]*\)\"$/\1/p" "$provenance")
    [[ -n $value && $value != *$'\n'* ]] || {
        echo "missing or duplicate provenance key: $1" >&2; exit 1;
    }
    printf '%s' "$value"
}
source_revision=$(manifest_value system_templates_source_revision)
builder_revision=$(manifest_value system_templates_builder_revision)
runtime_revision=$(manifest_value agent_runtime_source_revision)
host_toolchain=$(manifest_value host_toolchain)
guest_toolchain=$(manifest_value guest_toolchain)
for revision in "$source_revision" "$builder_revision" "$runtime_revision"; do
    [[ $revision =~ ^[0-9a-f]{40}$ ]] || exit 1
    git cat-file -e "${revision}^{commit}"
done
for toolchain in "$host_toolchain" "$guest_toolchain"; do
    [[ $toolchain =~ ^nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || exit 1
    rustup run "$toolchain" rustc --version
done

# Never default to /tmp: it may be RAM-backed. Keep failed candidates and logs
# for diagnosis; no release pin is overwritten by this verifier.
scratch_root="$repository_root/target/agent-release-reproduction"
mkdir -p "$scratch_root"
build_root=$(mktemp -d "$scratch_root/run.XXXXXX")
export TMPDIR="$build_root/tmp"
mkdir "$TMPDIR"
echo "reproduction evidence: $build_root"
export_source() {
    mkdir "$2"
    git archive "$1" | tar -xf - -C "$2"
    mkdir "$2/.git"
}
check_digest() {
    local expected actual
    expected=$(manifest_value "$1")
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || exit 1
    actual=$(b2sum -l 256 "$2")
    [[ ${actual%% *} == "$expected" ]] || {
        echo "digest mismatch for $1: $2" >&2; exit 1;
    }
}
export_source "$builder_revision" "$build_root/builder"
host_target="$scratch_root/host-$builder_revision"
(
    cd "$build_root/builder"
    CARGO_TARGET_DIR="$host_target" cargo "+$host_toolchain" build -p vosx --bin vosx
)
pinned_vosx="$host_target/debug/vosx"

if [[ $mode == all || $mode == system ]]; then
    export_source "$source_revision" "$build_root/system"
    "$pinned_vosx" release build-system-templates \
        --source "$build_root/system" --out "$build_root/templates"
    check_digest system_authority_package_blake2b_256 "$build_root/templates/system-authority.vos"
    check_digest system_catalog_package_blake2b_256 "$build_root/templates/system-catalog.vos"
    cmp "$build_root/templates/system-authority.vos" "$repository_root/vosx/blobs/system_authority.vos"
    cmp "$build_root/templates/system-catalog.vos" "$repository_root/vosx/blobs/system_catalog.vos"
fi
if [[ $mode == all || $mode == runtime ]]; then
    export_source "$runtime_revision" "$build_root/runtime"
    (
        cd "$build_root/runtime/services/agent-runtime"
        CARGO_TARGET_DIR="$build_root/runtime-target" cargo "+$guest_toolchain" actor
    )
    runtime_elf="$build_root/runtime-target/riscv64em-vos/release/agent_runtime.elf"
    check_digest agent_runtime_elf_blake2b_256 "$runtime_elf"
    "$pinned_vosx" agent-runtime-pvm "$runtime_elf" --out "$build_root/agent-runtime.pvm" \
        | tee "$build_root/runtime-identity.log"
    expected_program=$(manifest_value agent_runtime_program_id)
    [[ $expected_program =~ ^[0-9a-f]{64}$ ]] || exit 1
    rg -F "agent_runtime_program_id = $expected_program" "$build_root/runtime-identity.log"
    check_digest agent_runtime_pvm_blake2b_256 "$build_root/agent-runtime.pvm"
    cmp "$build_root/agent-runtime.pvm" "$repository_root/vosx/blobs/agent_runtime.pvm"
fi
echo "verified Agent-generation $mode artifacts from immutable sources"
