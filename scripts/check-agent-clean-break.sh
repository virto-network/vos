#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "clean-break check: $*" >&2
    exit 1
}

retired_paths=(
    services/vos-service
    actors/space-authority
    vosx/src/cli_cache.rs
    vosx/src/token.rs
    vosx/src/commands/dynamic.rs
    vosx/src/commands/space/access.rs
    vosx/src/commands/space/agent_authority.rs
    vosx/src/commands/space/agents.rs
    vosx/src/commands/space/apply.rs
    vosx/src/commands/space/authority_socket.rs
    vosx/src/commands/space/call.rs
    vosx/src/commands/space/describe.rs
    vosx/src/commands/space/export.rs
    vosx/src/commands/space/install.rs
    vosx/src/commands/space/invite.rs
    vosx/src/commands/space/members.rs
    vosx/src/commands/space/production_trust.rs
    vosx/src/commands/space/programs.rs
    vosx/src/commands/space/publish.rs
    vosx/src/commands/space/raft_status.rs
    vosx/src/commands/space/role.rs
    vosx/src/commands/space/subscriptions.rs
    vosx/src/commands/space/uninstall.rs
    vosx/src/commands/space/unpublish.rs
    vosx/src/commands/space/upgrade.rs
    vosx/tests/onboarding_e2e.rs
    vos/tests/service_pvm.rs
    vos/tests/actor_framework_hardening.rs
    tests/acceptance/clerk
    tests/fixtures/actors/service-counter
    tests/fixtures/actors/crdt-counter
    vos/tests/fixtures/counter-upgrade
    vos/tests/fixtures/crdt-counter
    vos/tests/fixtures/cycle
    vos/tests/fixtures/greeter
    vos/tests/fixtures/tally
    vos/tests/fixtures/workflow
)
for path in "${retired_paths[@]}"; do
    [[ ! -e $path ]] || fail "retired path remains: $path"
done

cargo build --locked -p vosx --bin vosx
binary="${CARGO_TARGET_DIR:-target}/debug/vosx"
top_help=$("$binary" --help)
space_help=$("$binary" space --help)
up_help=$("$binary" space up --help)
new_help=$("$binary" space new --help)

for command in actor agent-runtime-pvm release space zk help-schema whoami; do
    grep -Eq "^  ${command}([[:space:]]|$)" <<<"$top_help" \
        || fail "top-level help omits retained command '$command'"
done
for command in agent new build service-pvm; do
    if grep -Eq "^  ${command}([[:space:]]|$)" <<<"$top_help"; then
        fail "retired top-level command is advertised: $command"
    fi
done

for command in new list info up down backup restore caps forget; do
    grep -Eq "^  ${command}([[:space:]]|$)" <<<"$space_help" \
        || fail "space help omits retained command '$command'"
done
for command in access agents apply call describe export install invite members programs publish raft-status role subs uninstall unpublish upgrade; do
    if grep -Eq "^  ${command}([[:space:]]|$)" <<<"$space_help"; then
        fail "retired space command is advertised: $command"
    fi
done

for flag in --service-pvm --production-trust-socket --allow-conformance --agent-root-pins --agent-authority-socket; do
    grep -Fq -- "$flag" <<<"$up_help" && fail "retired space-up flag remains: $flag"
done
grep -Fq -- "--recipe" <<<"$new_help" && fail "retired space-new recipe flag remains"

if "$binary" worker stop >/dev/null 2>&1; then
    fail "unknown top-level words still enter a dynamic dispatcher"
fi

documentation=(
    README.md
    docs/getting-started.md
    docs/actors.md
    docs/extensions.md
    docs/http-ingress.md
    docs/ssh-ingress.md
    docs/operations.md
    extensions/substrate/README.md
)
retired_docs='vosx (agent (create|list|show|invite-node|revoke-node|recover)|actor (install|upgrade|suspend|resume|remove)|call|new|build|service-pvm)|vosx space (access|agents|apply|call|describe|export|install|invite|members|programs|publish|raft-status|role|subs|uninstall|unpublish|upgrade)|--(service-pvm|production-trust-socket|allow-conformance|agent-root-pins|agent-authority-socket|recipe)'
if rg -n "$retired_docs" "${documentation[@]}"; then
    fail "documentation advertises retired compatibility commands"
fi

echo "clean-break check: retained CLI and negative surface verified"
