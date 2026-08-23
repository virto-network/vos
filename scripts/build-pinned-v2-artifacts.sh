#!/usr/bin/env bash
set -euo pipefail

mode=${1:-all}
case "$mode" in
    all | service | clerk) ;;
    *)
        echo "usage: $0 [all|service|clerk]" >&2
        exit 2
        ;;
esac

repository_root=$(git rev-parse --show-toplevel)
provenance="$repository_root/support/v2-production-artifacts.toml"
manifest_value() {
    local key=$1
    sed -n "s/^${key} = \"\([^\"]*\)\"$/\1/p" "$provenance"
}
source_revision=$(manifest_value source_revision)
guest_toolchain=$(manifest_value guest_toolchain)
host_toolchain=$(manifest_value host_toolchain)
service_elf_digest=$(manifest_value service_elf_blake2b_256)
service_pvm_digest=$(manifest_value service_pvm_blake2b_256)
clerk_program=$(manifest_value clerk_actor_program_id)
clerk_deployment=$(manifest_value clerk_deployment_id)
clerk_task=$(manifest_value clerk_task_hash)
for value in \
    "$source_revision" "$guest_toolchain" "$host_toolchain" \
    "$service_elf_digest" "$service_pvm_digest" \
    "$clerk_program" "$clerk_deployment" "$clerk_task"
do
    if [[ -z $value ]]; then
        echo "incomplete v2 artifact provenance: $provenance" >&2
        exit 1
    fi
done
if [[ ! $source_revision =~ ^[0-9a-f]{40}$ ]] \
    || [[ ! $guest_toolchain =~ ^[A-Za-z0-9._-]+$ ]] \
    || [[ ! $host_toolchain =~ ^[A-Za-z0-9._-]+$ ]]
then
    echo "invalid source revision or toolchain in $provenance" >&2
    exit 1
fi
for digest in \
    "$service_elf_digest" "$service_pvm_digest" \
    "$clerk_program" "$clerk_deployment" "$clerk_task"
do
    if [[ ! $digest =~ ^[0-9a-f]{64}$ ]]; then
        echo "invalid v2 artifact identity in $provenance: $digest" >&2
        exit 1
    fi
done
git -C "$repository_root" cat-file -e "${source_revision}^{commit}" 2>/dev/null || {
    echo "pinned v2 source revision $source_revision is unavailable; fetch complete repository history" >&2
    exit 1
}
rustup run "$guest_toolchain" rustc --version >/dev/null
rustup run "$host_toolchain" rustc --version >/dev/null

build_root=$(mktemp -d "${TMPDIR:-/tmp}/vos-v2-artifacts.XXXXXX")
cleanup() {
    rm -rf -- "$build_root"
}
trap cleanup EXIT

git -C "$repository_root" archive --format=tar "$source_revision" | tar -xf - -C "$build_root"
# The canonical actor wrapper discovers the repository boundary through the
# checkout's .git entry. `git archive` intentionally omits it, so recreate a
# directory marker in the disposable source tree; otherwise actor and Task
# builds would remap different subtrees and derive different identities.
mkdir "$build_root/.git"

cache_root="$repository_root/target/pinned-v2-build/$source_revision"
artifact_root="$repository_root/target/pinned-v2-artifacts"
mkdir -p "$cache_root" "$artifact_root"

if [[ $mode == all || $mode == service ]]; then
    (
        cd "$build_root/services/vos-service"
        CARGO_TARGET_DIR="$cache_root/service" cargo "+$guest_toolchain" actor
    )
    service_elf="$cache_root/service/riscv64em-javm/release/vos_service.elf"
    actual_elf_digest=$(b2sum -l 256 "$service_elf")
    actual_elf_digest=${actual_elf_digest%% *}
    if [[ $actual_elf_digest != "$service_elf_digest" ]]; then
        echo "pinned service ELF digest mismatch: expected $service_elf_digest, got $actual_elf_digest" >&2
        exit 1
    fi
    actual_pvm_digest=$(b2sum -l 256 "$repository_root/services/vos-service/vos-service.pvm")
    actual_pvm_digest=${actual_pvm_digest%% *}
    if [[ $actual_pvm_digest != "$service_pvm_digest" ]]; then
        echo "committed service PVM digest mismatch: expected $service_pvm_digest, got $actual_pvm_digest" >&2
        exit 1
    fi
    install -m 0644 \
        "$service_elf" \
        "$artifact_root/vos_service.elf"
fi

if [[ $mode == all || $mode == clerk ]]; then
    # The canonical rustc wrapper is itself part of the artifact-producing
    # implementation. Use the pinned revision's vosx, not the moving binary
    # from HEAD. That revision selected `+nightly` literally; rewrite only
    # those toolchain arguments in the disposable export so rustup resolves
    # the recorded date-specific nightly instead of today's alias.
    sed -i "s/+nightly/+${guest_toolchain}/g" \
        "$build_root/vosx/src/commands/build.rs"
    clerk_log="$build_root/clerk-build.log"
    (
        cd "$build_root"
        CARGO_TARGET_DIR="$cache_root/host" \
            cargo "+$host_toolchain" run -p vosx -- build \
                "$build_root/actors/clerk-ledger" \
                --name clerk-ledger \
                --version production-v2 \
                --task "$build_root/tests/fixtures/provable/clerk-apply" \
                --out-dir "$build_root/target/v2-clerk"
    ) | tee "$clerk_log"
    for expected in \
        "program_id   = $clerk_program" \
        "deployment_id = $clerk_deployment" \
        "task[0]      = $clerk_task"
    do
        if ! grep -Fq "$expected" "$clerk_log"; then
            echo "pinned Clerk identity missing from build output: $expected" >&2
            exit 1
        fi
    done
    mkdir -p "$repository_root/target/v2-clerk"
    install -m 0644 \
        "$build_root/target/v2-clerk/clerk-ledger.vos" \
        "$repository_root/target/v2-clerk/clerk-ledger.vos"
    install -m 0644 \
        "$build_root/target/v2-clerk/clerk-ledger.pvm" \
        "$repository_root/target/v2-clerk/clerk-ledger.pvm"
fi
