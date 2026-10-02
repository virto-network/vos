#!/usr/bin/env bash
# Reproduce Agent-generation pins, or prepare independently checked Shared candidates.
set -euo pipefail

mode=${1:-all}
case "$mode" in
    all|runtime|system) ;;
    shared-candidate)
        [[ $# == 4 && $2 =~ ^[0-9a-f]{40}$ && -f $3 && ! -L $3 && -f $4 && ! -L $4 ]] || {
            echo "usage: $0 shared-candidate <40-hex-source-commit> <Clerk-signer-key> <explicit-external-limits-json> (regular files, no symlinks)" >&2
            exit 2
        }
        candidate_revision=$2
        clerk_signer=$(realpath "$3")
        role_limits=$(realpath "$4")
        [[ ! $clerk_signer -ef $role_limits ]] || {
            echo "external limits must not alias the Clerk signer file" >&2
            exit 2
        }
        [[ -s $role_limits && $(wc -c < "$role_limits") -le 8192 ]] || {
            echo "explicit external limits must be a nonempty JSON file of at most 8192 bytes" >&2
            exit 2
        }
        ;;
    *)
        echo "usage: $0 [all|runtime|system] | shared-candidate <40-hex-source-commit> <Clerk-signer-key> <explicit-external-limits-json>" >&2
        exit 2
        ;;
esac
repository_root=$(git rev-parse --show-toplevel)
provenance="$repository_root/support/production-artifacts.toml"
manifest_value() {
    local value
    if [[ $mode == shared-candidate ]]; then
        value=$(git show "$candidate_revision:support/production-artifacts.toml" \
            | sed -n "s/^$1 = \"\([^\"]*\)\"$/\1/p")
    else
        value=$(sed -n "s/^$1 = \"\([^\"]*\)\"$/\1/p" "$provenance")
    fi
    [[ -n $value && $value != *$'\n'* ]] || {
        echo "missing or duplicate provenance key: $1" >&2; exit 1;
    }
    printf '%s' "$value"
}
if [[ $mode == shared-candidate ]]; then
    source_revision=$candidate_revision
    builder_revision=$candidate_revision
    runtime_revision=$candidate_revision
else
    source_revision=$(manifest_value system_templates_source_revision)
    builder_revision=$(manifest_value system_templates_builder_revision)
    runtime_revision=$(manifest_value agent_runtime_source_revision)
fi
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
if [[ $mode == shared-candidate ]]; then
    # Candidate output is public, but the explicit signer copy must stay private.
    umask 077
    export CARGO_NET_OFFLINE=true
fi
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
host_features=()
if [[ $mode == shared-candidate || $mode == all || $mode == system ]]; then
    host_features=(--features experimental-state-blocks)
fi
if [[ $mode == shared-candidate ]]; then
    # Do not share mutable builder output with the pin-verification modes.
    host_target="$build_root/host-target"
fi
(
    cd "$build_root/builder"
    CARGO_TARGET_DIR="$host_target" cargo "+$host_toolchain" build --locked \
        -p vosx --bin vosx "${host_features[@]}"
) 2>&1 | tee "$build_root/builder.log"
pinned_vosx="$host_target/debug/vosx"

if [[ $mode == shared-candidate ]]; then
    # One immutable input set feeds a later coherent role repin. Signed role
    # templates are not a release bundle, selection grant or capacity evidence.
    # Limits are explicit input, never shell defaults or ABI-probe ceilings.
    signer_config="$build_root/clerk-signer-config"
    mkdir -p "$signer_config/vosx"
    signer_copy="$signer_config/vosx/identity.key"
    role_limits_copy="$build_root/external-state-limits.json"
    # Keep failed public artifacts/logs, but never retain the temporary secret.
    # Invalid JSON may itself be sensitive; remove that task-specific copy on
    # failure. Neither original caller file is modified or removed.
    trap 'artifact_exit=$?; rm -f -- "$signer_copy"; if (( artifact_exit != 0 )); then rm -f -- "$role_limits_copy"; fi' EXIT
    install -m 0600 "$clerk_signer" "$signer_copy"
    install -m 0600 "$role_limits" "$role_limits_copy"
    [[ -s $role_limits_copy && $(wc -c < "$role_limits_copy") -le 8192 ]] || exit 1
    printf 'source_revision = %s\nbuilder_revision = %s\nhost_toolchain = %s\nguest_toolchain = %s\n' \
        "$source_revision" "$builder_revision" "$host_toolchain" "$guest_toolchain" \
        > "$build_root/provenance.txt"
    rustup run "$host_toolchain" rustc --version --verbose > "$build_root/host-toolchain.log"
    rustup run "$guest_toolchain" rustc --version --verbose > "$build_root/guest-toolchain.log"
    # Retain the exact contract declarations alongside the immutable source ID;
    # the external metadata ceiling and ABI must not be inferred from image pins.
    cp "$build_root/builder/vos-agent-sdk/src/contract.rs" "$build_root/runtime-contract.rs"
    cp "$build_root/builder/vos-agent-sdk/src/state_execution.rs" "$build_root/state-execution-contract.rs"
    cp "$build_root/builder/vos-agent-sdk/src/lib.rs" "$build_root/runtime-abi-identities.rs"
    for pass in first second; do
        pass_root="$build_root/$pass"
        mkdir "$pass_root"
        pass_source="$pass_root/source"
        export_source "$source_revision" "$pass_source"
        cp "$pass_source/actors/clerk-ledger/Cargo.lock" "$pass_root/clerk.Cargo.lock"
        # The existing runtime wrapper remaps the whole source root. Keeping
        # Cargo output under that root also normalizes independent target paths.
        # Compile System's observation image separately from Local. The linker
        # checks its ordinary mutation ABI here; paired role materialization
        # below additionally runs real Observe and rejects state-changing
        # actor output before signing the observation opt-in.
        image_runtime_target="$pass_source/target/system-image-runtime"
        (
            cd "$pass_source/services/agent-runtime"
            CARGO_TARGET_DIR="$image_runtime_target" cargo "+$guest_toolchain" actor \
                --offline --locked --features system-observation
        ) 2>&1 | tee "$pass_root/system-image-runtime-build.log"
        "$pinned_vosx" agent-runtime-pvm \
            "$image_runtime_target/riscv64em-vos/release/agent_runtime.elf" \
            --out "$pass_root/system-image-runtime.pvm" \
            2>&1 | tee "$pass_root/system-image-runtime-identity.log"
        runtime_target="$pass_source/target/state-runtime"
        (
            cd "$pass_source/services/agent-runtime"
            CARGO_TARGET_DIR="$runtime_target" cargo "+$guest_toolchain" actor \
                --offline --locked --features experimental-state-blocks
        ) 2>&1 | tee "$pass_root/runtime-build.log"
        "$pinned_vosx" agent-runtime-pvm \
            "$runtime_target/riscv64em-vos/release/agent_runtime.elf" \
            --out "$pass_root/external-shared-runtime.pvm" --experimental-state-blocks \
            2>&1 | tee "$pass_root/runtime-identity.log"
        # Build Authority from the same contract revision as both runtimes.
        # The existing public template signer confers no deployment authority;
        # each Space still signs and admits its own exact package closure.
        CARGO_TARGET_DIR="$pass_source/target/system-templates" \
            "$pinned_vosx" release build-system-templates \
                --source "$pass_source" --out "$pass_root/system-templates" \
                --experimental-state-blocks \
                --system-runtime-pvm "$pass_root/system-image-runtime.pvm" \
                --shared-runtime-pvm "$pass_root/external-shared-runtime.pvm" \
                --external-state-limits "$role_limits_copy" \
                2>&1 | tee "$pass_root/system-templates-build.log"
        XDG_CONFIG_HOME="$signer_config" "$pinned_vosx" actor build \
            "$pass_source/actors/clerk-ledger" --feature agent --name clerk-ledger \
            --out-dir "$pass_root/clerk" 2>&1 | tee "$pass_root/clerk-identity.log"
        # The canonical actor builder launches Cargo internally. Offline mode
        # prevents fetching; an unchanged lock is also mandatory for acceptance.
        cmp "$pass_root/clerk.Cargo.lock" "$pass_source/actors/clerk-ledger/Cargo.lock"
        cmp "$clerk_signer" "$signer_copy"
        cmp "$role_limits" "$role_limits_copy"
    done
    cmp "$build_root/first/source/target/system-image-runtime/riscv64em-vos/release/agent_runtime.elf" \
        "$build_root/second/source/target/system-image-runtime/riscv64em-vos/release/agent_runtime.elf"
    cmp "$build_root/first/source/target/state-runtime/riscv64em-vos/release/agent_runtime.elf" \
        "$build_root/second/source/target/state-runtime/riscv64em-vos/release/agent_runtime.elf"
    for artifact in system-image-runtime.pvm external-shared-runtime.pvm \
        system-templates/system-authority.vos system-templates/system-catalog.vos \
        system-templates/system-image-runtime.vos system-templates/shared-external-runtime.vos \
        clerk/clerk-ledger.pvm clerk/clerk-ledger.vos; do
        cmp "$build_root/first/$artifact" "$build_root/second/$artifact"
        b2sum -l 256 "$build_root/first/$artifact" >> "$build_root/digests.txt"
    done
    b2sum -l 256 "$build_root/first/source/target/system-image-runtime/riscv64em-vos/release/agent_runtime.elf" \
        "$build_root/first/source/target/state-runtime/riscv64em-vos/release/agent_runtime.elf" \
        "$build_root/first/system-image-runtime-identity.log" \
        "$build_root/second/system-image-runtime-identity.log" \
        "$pinned_vosx" "$build_root/runtime-contract.rs" \
        "$build_root/state-execution-contract.rs" "$build_root/runtime-abi-identities.rs" \
        >> "$build_root/digests.txt"
    # Exact signed roles feed one coherent repin; they are not production
    # selections until release and workflow qualification. Signed ceilings are
    # explicit declarations, not measured storage capacity.
    candidate_runtime_program() {
        local program
        program=$(sed -n 's/^  agent_runtime_program_id = //p' "$1")
        [[ $program =~ ^[0-9a-f]{64}$ ]] || {
            echo "missing or duplicate runtime program identity: $1" >&2; exit 1;
        }
        printf '%s' "$program"
    }
    image_program=$(candidate_runtime_program "$build_root/first/system-image-runtime-identity.log")
    external_program=$(candidate_runtime_program "$build_root/first/runtime-identity.log")
    [[ $image_program == "$(candidate_runtime_program "$build_root/second/system-image-runtime-identity.log")" ]]
    [[ $external_program == "$(candidate_runtime_program "$build_root/second/runtime-identity.log")" ]]
    # Record the existing Local pin without rebuilding, renaming, or replacing
    # its blob. The builder export is from the requested immutable commit.
    local_runtime="$build_root/builder/vosx/blobs/agent_runtime.pvm"
    check_digest agent_runtime_pvm_blake2b_256 "$local_runtime"
    local_program=$(manifest_value agent_runtime_program_id)
    [[ $local_program =~ ^[0-9a-f]{64}$ ]] || exit 1
    {
        printf 'format = 1\nqualification = "candidate-only"\n'
        printf 'source_revision = "%s"\nbuilder_revision = "%s"\n' "$source_revision" "$builder_revision"
        printf 'host_toolchain = "%s"\nguest_toolchain = "%s"\n' "$host_toolchain" "$guest_toolchain"
        printf 'runtime_contract_source = "runtime-contract.rs"\nstate_execution_contract_source = "state-execution-contract.rs"\n'
        printf 'runtime_abi_source = "runtime-abi-identities.rs"\n'
        printf 'signed_runtime_envelopes = "two-independent-builds"\nexternal_storage_ceilings = "explicit-not-measured"\n'
        printf 'external_limits_input = "external-state-limits.json"\n'
        printf '\n[local_image]\nprovenance = "unchanged-release-pin"\n'
        printf 'source_revision = "%s"\npinned_program_id = "%s"\n' "$(manifest_value agent_runtime_source_revision)" "$local_program"
        printf 'pvm = "builder/vosx/blobs/agent_runtime.pvm"\npvm_bytes = %s\npvm_blake2b_256 = "%s"\n' \
            "$(wc -c < "$local_runtime")" "$(manifest_value agent_runtime_pvm_blake2b_256)"
        for role in system_image shared_external; do
            case "$role" in
                system_image)
                    pvm=system-image-runtime.pvm
                    elf=source/target/system-image-runtime/riscv64em-vos/release/agent_runtime.elf
                    program=$image_program
                    package=system-templates/system-image-runtime.vos
                    ;;
                shared_external)
                    pvm=external-shared-runtime.pvm
                    elf=source/target/state-runtime/riscv64em-vos/release/agent_runtime.elf
                    program=$external_program
                    package=system-templates/shared-external-runtime.vos
                    ;;
            esac
            pvm_digest=$(b2sum -l 256 "$build_root/first/$pvm")
            elf_digest=$(b2sum -l 256 "$build_root/first/$elf")
            package_digest=$(b2sum -l 256 "$build_root/first/$package")
            printf '\n[%s]\nprovenance = "two-independent-builds"\nprogram_id = "%s"\n' "$role" "$program"
            if [[ $role == system_image ]]; then
                printf 'guest_features = "system-observation"\ncontract_constructor = "RuntimePackageContract::system_observation_image"\nauthority_configuration_magic = "SAC7"\n'
                printf 'mutation_wire_contract = "unchanged RUNTIME_ABI_ID"\nobservation_workflow_qualification = "pending"\n'
            else
                printf 'guest_features = "experimental-state-blocks"\ncontract_constructor = "RuntimePackageContract::experimental_state_blocks"\n'
            fi
            printf 'pvm = "first/%s"\npvm_bytes = %s\npvm_blake2b_256 = "%s"\n' \
                "$pvm" "$(wc -c < "$build_root/first/$pvm")" "${pvm_digest%% *}"
            printf 'elf = "first/%s"\nelf_bytes = %s\nelf_blake2b_256 = "%s"\n' \
                "$elf" "$(wc -c < "$build_root/first/$elf")" "${elf_digest%% *}"
            printf 'signed_package = "first/%s"\npackage_bytes = %s\npackage_blake2b_256 = "%s"\n' \
                "$package" "$(wc -c < "$build_root/first/$package")" "${package_digest%% *}"
        done
    } > "$build_root/runtime-role-inputs.toml"
    b2sum -l 256 "$build_root/runtime-role-inputs.toml" >> "$build_root/digests.txt"
    b2sum -l 256 "$role_limits_copy" >> "$build_root/digests.txt"
    echo "verified two independent System image, external runtime, Authority/Catalog template, and signed Clerk Agent candidate builds"
    echo "outputs: $build_root/first/system-image-runtime.pvm, $build_root/first/external-shared-runtime.pvm, and $build_root/first/clerk/clerk-ledger.vos"
    echo "candidate role evidence: $build_root/runtime-role-inputs.toml (not a production manifest or selection grant)"
    echo "OPEN: coherent role repin/release manifest, bundled selection, and fixed-three SAC7 workflow/capacity qualification"
    exit 0
fi

if [[ $mode == all || $mode == system ]]; then
    export_source "$source_revision" "$build_root/system"
    "$pinned_vosx" release build-system-templates \
        --source "$build_root/system" --out "$build_root/templates" \
        --experimental-state-blocks
    check_digest system_authority_package_blake2b_256 "$build_root/templates/system-authority.vos"
    check_digest system_catalog_package_blake2b_256 "$build_root/templates/system-catalog.vos"
    cmp "$build_root/templates/system-authority.vos" "$repository_root/vosx/blobs/system_authority.vos"
    cmp "$build_root/templates/system-catalog.vos" "$repository_root/vosx/blobs/system_catalog.vos"
    # The released builder must materialize and verify the complete exact-role
    # bundle. An older four-file bundle is not current production evidence.
    # No runtime paths, limits or candidate overrides are supplied here.
    "$pinned_vosx" release bundle --out "$build_root/release"
    "$pinned_vosx" release verify "$build_root/release"
    [[ -f $build_root/release/system-image-runtime.vos && -f $build_root/release/shared-external-runtime.vos ]]
    check_digest system_image_runtime_package_blake2b_256 "$build_root/release/system-image-runtime.vos"
    check_digest shared_external_runtime_package_blake2b_256 "$build_root/release/shared-external-runtime.vos"
    cmp "$build_root/release/system-image-runtime.vos" "$repository_root/vosx/blobs/system_image_runtime.vos"
    cmp "$build_root/release/shared-external-runtime.vos" "$repository_root/vosx/blobs/shared_external_runtime.vos"
fi
if [[ $mode == all || $mode == runtime ]]; then
    export_source "$runtime_revision" "$build_root/runtime"
    (
        cd "$build_root/runtime/services/agent-runtime"
        CARGO_TARGET_DIR="$build_root/runtime-target" cargo "+$guest_toolchain" actor --locked
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
