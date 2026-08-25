#!/usr/bin/env bash
set -euo pipefail

mode=${1:-all}
case "$mode" in
    all | service | authority | registry | clerk | clerk-test) ;;
    *)
        echo "usage: $0 [all|service|authority|registry|clerk|clerk-test] [clerk-signer-key]" >&2
        exit 2
        ;;
esac
clerk_signer=${2:-}
if [[ $mode == all || $mode == clerk ]]; then
    if [[ -z $clerk_signer ]]; then
        echo "signed Clerk packaging requires an explicit libp2p signer key path" >&2
        echo "usage: $0 $mode <clerk-signer-key>" >&2
        exit 2
    fi
    if [[ ! -f $clerk_signer ]]; then
        echo "Clerk signer is not a regular file: $clerk_signer" >&2
        exit 1
    fi
    clerk_signer=$(realpath "$clerk_signer")
fi

repository_root=$(git rev-parse --show-toplevel)
provenance="$repository_root/support/production-artifacts.toml"
manifest_value() {
    local key=$1
    sed -n "s/^${key} = \"\([^\"]*\)\"$/\1/p" "$provenance"
}
source_revision=$(manifest_value source_revision)
guest_toolchain=$(manifest_value guest_toolchain)
host_toolchain=$(manifest_value host_toolchain)
service_elf_digest=$(manifest_value service_elf_blake2b_256)
service_pvm_digest=$(manifest_value service_pvm_blake2b_256)
service_program=$(manifest_value service_program_id)
authority_pvm_digest=$(manifest_value authority_pvm_blake2b_256)
authority_program=$(manifest_value authority_program_id)
registry_elf_digest=$(manifest_value registry_elf_blake2b_256)
clerk_program=$(manifest_value clerk_actor_program_id)
clerk_deployment=$(manifest_value clerk_deployment_id)
clerk_task=$(manifest_value clerk_task_hash)
for value in \
    "$source_revision" "$guest_toolchain" "$host_toolchain" \
    "$service_elf_digest" "$service_pvm_digest" "$service_program" \
    "$authority_pvm_digest" "$authority_program" \
    "$registry_elf_digest" \
    "$clerk_program" "$clerk_deployment" "$clerk_task"
do
    if [[ -z $value ]]; then
        echo "incomplete service artifact provenance: $provenance" >&2
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
    "$service_elf_digest" "$service_pvm_digest" "$service_program" \
    "$authority_pvm_digest" "$authority_program" \
    "$registry_elf_digest" \
    "$clerk_program" "$clerk_deployment" "$clerk_task"
do
    if [[ ! $digest =~ ^[0-9a-f]{64}$ ]]; then
        echo "invalid service artifact identity in $provenance: $digest" >&2
        exit 1
    fi
done
git -C "$repository_root" cat-file -e "${source_revision}^{commit}" 2>/dev/null || {
    echo "pinned service source revision $source_revision is unavailable; fetch complete repository history" >&2
    exit 1
}
rustup run "$guest_toolchain" rustc --version >/dev/null
rustup run "$host_toolchain" rustc --version >/dev/null

build_root=$(mktemp -d "${TMPDIR:-/tmp}/vos-artifacts.XXXXXX")
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

cache_root="$repository_root/target/pinned-production-build/$source_revision"
artifact_root="$repository_root/target/pinned-production-artifacts"
mkdir -p "$cache_root" "$artifact_root"

# Both artifact paths use the source revision's own wrapper/transpiler. That
# revision selected `+nightly` literally; rewrite only those toolchain
# arguments in the disposable export so rustup resolves the recorded
# date-specific guest toolchain instead of today's alias.
sed -i "s/+nightly/+${guest_toolchain}/g" \
    "$build_root/vosx/src/commands/build.rs"
(
    cd "$build_root"
    CARGO_TARGET_DIR="$cache_root/host" \
        cargo "+$host_toolchain" build -p vosx
)
pinned_vosx="$cache_root/host/debug/vosx"

if [[ $mode == all || $mode == service ]]; then
    (
        cd "$build_root/services/vos-service"
        CARGO_TARGET_DIR="$cache_root/service" cargo "+$guest_toolchain" actor
    )
    service_elf="$cache_root/service/riscv64em-vos/release/vos_service.elf"
    actual_elf_digest=$(b2sum -l 256 "$service_elf")
    actual_elf_digest=${actual_elf_digest%% *}
    if [[ $actual_elf_digest != "$service_elf_digest" ]]; then
        echo "pinned service ELF digest mismatch: expected $service_elf_digest, got $actual_elf_digest" >&2
        exit 1
    fi
    fresh_service_pvm="$build_root/vos-service.pvm"
    service_log="$build_root/service-pvm.log"
    "$pinned_vosx" service-pvm "$service_elf" --out "$fresh_service_pvm" \
        | tee "$service_log"
    if ! grep -Fq "service_program_id = $service_program" "$service_log"; then
        echo "pinned service ProgramId missing from transpiler output: $service_program" >&2
        exit 1
    fi
    actual_pvm_digest=$(b2sum -l 256 "$fresh_service_pvm")
    actual_pvm_digest=${actual_pvm_digest%% *}
    if [[ $actual_pvm_digest != "$service_pvm_digest" ]]; then
        echo "fresh service PVM digest mismatch: expected $service_pvm_digest, got $actual_pvm_digest" >&2
        exit 1
    fi
    if ! cmp -s "$fresh_service_pvm" "$repository_root/services/vos-service/vos-service.pvm"; then
        if [[ ${VOS_REPIN_ARTIFACTS:-0} != 1 ]]; then
            echo "fresh pinned service PVM differs from the committed artifact" >&2
            echo "set VOS_REPIN_ARTIFACTS=1 only for an intentional reviewed repin" >&2
            exit 1
        fi
        install -m 0644 \
            "$fresh_service_pvm" \
            "$repository_root/services/vos-service/vos-service.pvm"
    fi
    install -m 0644 \
        "$service_elf" \
        "$artifact_root/vos_service.elf"
    install -m 0644 \
        "$fresh_service_pvm" \
        "$artifact_root/vos-service.pvm"
fi

if [[ $mode == all || $mode == registry ]]; then
    registry_out="$build_root/target/registry"
    registry_config="$build_root/registry-signer-config"
    mkdir -p "$registry_config"
    (
        cd "$build_root"
        XDG_CONFIG_HOME="$registry_config" \
            "$pinned_vosx" build \
            "$build_root/actors/space-registry" \
            --name space-registry \
            --out-dir "$registry_out"
    )
    registry_elf="$build_root/actors/space-registry/target/vosx-canonical/riscv64em-vos/release/space_registry.elf"
    actual_registry_digest=$(b2sum -l 256 "$registry_elf")
    actual_registry_digest=${actual_registry_digest%% *}
    if [[ $actual_registry_digest != "$registry_elf_digest" ]]; then
        echo "fresh registry ELF digest mismatch: expected $registry_elf_digest, got $actual_registry_digest" >&2
        exit 1
    fi
    if ! cmp -s "$registry_elf" "$repository_root/vosx/blobs/space_registry.elf"; then
        if [[ ${VOS_REPIN_ARTIFACTS:-0} != 1 ]]; then
            echo "fresh pinned registry ELF differs from the committed artifact" >&2
            echo "set VOS_REPIN_ARTIFACTS=1 only for an intentional reviewed repin" >&2
            exit 1
        fi
        install -m 0644 \
            "$registry_elf" \
            "$repository_root/vosx/blobs/space_registry.elf"
    fi
    install -m 0644 \
        "$registry_elf" \
        "$artifact_root/space-registry.elf"
fi

if [[ $mode == all || $mode == authority ]]; then
    authority_out="$build_root/target/authority"
    authority_config="$build_root/authority-signer-config"
    authority_log="$build_root/authority-build.log"
    mkdir -p "$authority_config"
    (
        cd "$build_root"
        XDG_CONFIG_HOME="$authority_config" \
            "$pinned_vosx" build \
            "$build_root/actors/space-authority" \
            --name space-authority \
            --out-dir "$authority_out"
    ) | tee "$authority_log"
    if ! grep -Fq "program_id   = $authority_program" "$authority_log"; then
        echo "pinned authority ProgramId missing from build output: $authority_program" >&2
        exit 1
    fi
    fresh_authority_pvm="$authority_out/space-authority.pvm"
    actual_authority_digest=$(b2sum -l 256 "$fresh_authority_pvm")
    actual_authority_digest=${actual_authority_digest%% *}
    if [[ $actual_authority_digest != "$authority_pvm_digest" ]]; then
        echo "fresh authority PVM digest mismatch: expected $authority_pvm_digest, got $actual_authority_digest" >&2
        exit 1
    fi
    if ! cmp -s "$fresh_authority_pvm" "$repository_root/vosx/blobs/space_authority.pvm"; then
        if [[ ${VOS_REPIN_ARTIFACTS:-0} != 1 ]]; then
            echo "fresh pinned authority PVM differs from the committed artifact" >&2
            echo "set VOS_REPIN_ARTIFACTS=1 only for an intentional reviewed repin" >&2
            exit 1
        fi
        install -m 0644 \
            "$fresh_authority_pvm" \
            "$repository_root/vosx/blobs/space_authority.pvm"
    fi
    install -m 0644 \
        "$fresh_authority_pvm" \
        "$artifact_root/space-authority.pvm"
fi

if [[ $mode == all || $mode == clerk || $mode == clerk-test ]]; then
    # Package content is pinned by the actor ProgramId, DeploymentId and Task
    # hash below. The final `.vos` envelope also names and is signed by an
    # operator, so it is deliberately a separate release step. Production
    # builds must select that signer explicitly; fixture builds use an
    # isolated ephemeral identity and are never release artifacts.
    signer_config="$build_root/clerk-signer-config"
    mkdir -p "$signer_config/vosx"
    if [[ $mode == all || $mode == clerk ]]; then
        install -m 0600 "$clerk_signer" "$signer_config/vosx/identity.key"
        echo "signing pinned Clerk content with explicit key: $clerk_signer"
    else
        echo "building test-only Clerk package with an isolated ephemeral signer"
    fi
    clerk_log="$build_root/clerk-build.log"
    (
        cd "$build_root"
        XDG_CONFIG_HOME="$signer_config" \
            "$pinned_vosx" build \
            "$build_root/actors/clerk-ledger" \
            --name clerk-ledger \
            --task "$build_root/tests/fixtures/provable/clerk-apply" \
            --out-dir "$build_root/target/clerk"
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
    mkdir -p "$repository_root/target/clerk"
    package_digest=$(b2sum -l 256 "$build_root/target/clerk/clerk-ledger.vos")
    package_digest=${package_digest%% *}
    if [[ $mode == clerk-test ]]; then
        echo "  test_package_blake2b_256 = $package_digest (ephemeral; not a release pin)"
    else
        echo "  signed_package_blake2b_256 = $package_digest"
    fi
    install -m 0644 \
        "$build_root/target/clerk/clerk-ledger.vos" \
        "$repository_root/target/clerk/clerk-ledger.vos"
    install -m 0644 \
        "$build_root/target/clerk/clerk-ledger.pvm" \
        "$repository_root/target/clerk/clerk-ledger.pvm"
fi
