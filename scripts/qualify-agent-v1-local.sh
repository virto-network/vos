#!/usr/bin/env bash
# Direct released-CLI, three-process local qualification; no fixture gates/signers.
# Usage: bash qualify-agent-v1-local.sh VOSX SHA256 RELEASE_DIR CLERK_PACKAGE FRESH_EVIDENCE_DIR BASE_PORT
# Only the newly generated disposable Root is copied to these three personas.
# This is NOT a production secret-distribution procedure. Evidence retains keys
# privately; nothing is deleted. No load/hardware/non-root/fault acceptance inferred.
set -euo pipefail
umask 077
fail() { echo "qualification refused: $*" >&2; exit 1; }
(( $# == 6 )) || fail "expected VOSX SHA256 RELEASE_DIR CLERK_PACKAGE FRESH_EVIDENCE_DIR BASE_PORT"
for tool in realpath stat id sha256sum install mkdir jq curl ss timeout date awk sed env dirname ls wc sleep python3; do
    command -v "$tool" >/dev/null || fail "missing $tool"
done
while IFS= read -r variable; do
    case "$variable" in
        *CANDIDATE*|VOS_TEST_*|VOSX_EXPERIMENTAL_*|VOSX_QUALIFY_*|CLERK_AGENT_PACKAGE)
            fail "candidate/test override environment is forbidden: $variable" ;;
    esac
done < <(compgen -e)
checked_path() {
    local canonical
    [[ -e $1 && ! -L $1 ]] || fail "missing or symlink input: $1"
    canonical=$(realpath -e -- "$1")
    [[ $canonical == "$(realpath -ms -- "$1")" ]] || fail "symlink path component: $1"
    case "$canonical" in *$'\n'*|*$'\r'*|*'"'*|*'\'*) fail "unsupported path spelling" ;; esac
    printf '%s' "$canonical"
}
binary_source=$(checked_path "$1"); expected_sha=$2
release_source=$(checked_path "$3"); clerk_source=$(checked_path "$4")
[[ -f $binary_source && -x $binary_source && -d $release_source && -f $clerk_source && -s $clerk_source ]] || fail "invalid artifact inputs"
[[ $expected_sha =~ ^[0-9a-f]{64}$ && $(sha256sum "$binary_source" | awk '{print $1}') == "$expected_sha" ]] || fail "executable SHA256 mismatch"
evidence_parent=$(checked_path "$(dirname -- "$5")")
[[ -d $evidence_parent && $(stat -c %u "$evidence_parent") == "$(id -u)" ]] || fail "evidence parent must be an owned directory"
(( (8#$(stat -c %a "$evidence_parent") & 077) == 0 )) || fail "evidence parent must be private (0700)"
case $(stat -f -c %T "$evidence_parent") in tmpfs|ramfs|devtmpfs|hugetlbfs) fail "evidence must be disk-backed" ;; esac
evidence=$(realpath -ms -- "$5")
[[ ! -e $evidence && ! -L $evidence && $(dirname -- "$evidence") == "$evidence_parent" ]] || fail "evidence root must be fresh and non-symlink"
case "$evidence" in *$'\n'*|*$'\r'*|*'"'*|*'\'*) fail "unsupported evidence spelling" ;; esac
[[ $6 =~ ^[1-9][0-9]{3,4}$ ]] || fail "BASE_PORT must be decimal, at least 1024"
base_port=$6
(( base_port >= 1024 && base_port + 8 <= 65535 )) || fail "port range outside 1024..65535"
listeners=$(ss -H -ltn)
for ((port=base_port; port<=base_port+8; port++)); do
    ! awk '{print $4}' <<< "$listeners" | awk -v port="$port" '$0 ~ ":" port "$" {found=1} END {exit !found}' || fail "port occupied: $port"
done
mkdir -m 0700 -- "$evidence"
mkdir -- "$evidence/logs" "$evidence/tmp" "$evidence/release" "$evidence/enrollments"
install -m 0700 -- "$binary_source" "$evidence/vosx"
install -m 0600 -- "$clerk_source" "$evidence/clerk-ledger.vos"
install -m 0600 -- "${BASH_SOURCE[0]}" "$evidence/qualification.sh"
binary="$evidence/vosx"; clerk="$evidence/clerk-ledger.vos"
[[ $(sha256sum "$binary" | awk '{print $1}') == "$expected_sha" ]] || fail "copied executable changed"
roles=(manifest.json standard-runtime.pvm system-image-runtime.vos shared-external-runtime.vos system-authority.vos system-catalog.vos)
for role in "${roles[@]}"; do
    source=$(checked_path "$release_source/$role")
    [[ -f $source && -s $source ]] || fail "missing release role: $role"
    install -m 0600 -- "$source" "$evidence/release/$role"
done
[[ $(ls -A -- "$release_source" | wc -l) == 6 ]] || fail "release directory must contain exactly six files"
sha256sum "$binary" "$clerk" "$evidence/qualification.sh" "$evidence/release/"* > "$evidence/artifacts.sha256"
printf 'step\tstarted_unix_ms\telapsed_ms\texit_code\n' > "$evidence/timings.tsv"
printf '%s\n' "TEST ONLY: generated Root copied to three isolated local personas, never production key distribution." \
    "OPEN: non-root role workflows, mutating Clerk workload, lost-response injection, exact all-member commit/apply parity, load/hardware and latency qualification." > "$evidence/acceptance.txt"
echo "private qualification evidence: $evidence"
pids=(); pid_starts=(); name=packaged-v1
# stat field 22 identifies this launch even after numeric PID reuse. Strip the
# parenthesized comm first, so spaces/parentheses do not shift the field index.
process_identity() {
    local record tail
    local -a fields
    [[ -r /proc/$1/stat ]] || return 1
    IFS= read -r record < "/proc/$1/stat" || return 1
    tail=${record##*) }
    read -ra fields <<< "$tail"
    [[ ${#fields[@]} -ge 20 && ${fields[19]} =~ ^[0-9]+$ && ${fields[1]} == "$$" ]] || return 1
    printf '%s %s' "${fields[19]}" "${fields[0]}"
}
owned_live() {
    local identity state
    identity=$(process_identity "$1") || return 1
    state=${identity#* }
    [[ ${identity%% *} == "$2" && $state != Z && $state != X && $state != x ]]
}
cli_bounded() {
    local persona=$1 duration=$2; shift 2
    timeout --signal=TERM --kill-after=10s "$duration" env XDG_DATA_HOME="$evidence/$persona/data" XDG_CONFIG_HOME="$evidence/$persona/config" \
        XDG_CACHE_HOME="$evidence/$persona/cache" TMPDIR="$evidence/tmp" VOSX_DISABLE_MDNS=1 \
        RUST_LOG=info "$binary" --format json "$@"
}
cli() { local persona=$1; shift; cli_bounded "$persona" 180s "$@"; }
run() {
    local step=$1 persona=$2 started code=0; shift 2
    started=$(date +%s%3N)
    cli "$persona" "$@" > "$evidence/logs/$step.stdout" 2> "$evidence/logs/$step.stderr" || code=$?
    printf '%s\t%s\t%s\t%s\n' "$step" "$started" "$(( $(date +%s%3N) - started ))" "$code" >> "$evidence/timings.tsv"
    (( code == 0 )) || fail "$step failed ($code); inspect retained logs"
}
monotonic_ms() { python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)'; }
lifecycle_fence() {
    # These private hashes are a delivery fence, not a wire/authentication
    # decoder. The ordinary CLI still validates Space, credential, nonce and
    # signed request. This fresh persona has one serialized client operation.
    python3 - "$1" "$evidence/$2/space/agent-client" "$space_id" "$evidence/logs/$3.binding.json" "$3.request" <<'PY'
import hashlib, json, re, sys
from pathlib import Path

mode, client_path, space, state_path, request_name = sys.argv[1:]
client, state_file = Path(client_path), Path(state_path)

def refuse():
    raise SystemExit("qualification refused: lifecycle operation binding changed; inspect private evidence")

def entries(directory):
    if not directory.exists():
        return []
    if directory.is_symlink() or not directory.is_dir():
        refuse()
    values = list(directory.iterdir())
    if any(value.is_symlink() for value in values):
        refuse()
    return values

def digest(path):
    if path.is_symlink() or not path.is_file():
        refuse()
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

def files(directory):
    result = {}
    for path in entries(directory):
        if path.name == "lock":
            continue
        if path.is_dir():
            for name, value in files(path).items():
                result[f"{path.name}/{name}"] = value
        else:
            result[path.name] = digest(path)
    return result

operations = entries(client / "operations")
if any(not path.is_dir() or not re.fullmatch(r"[0-9a-f]{64}-[0-9a-f]{64}", path.name) for path in operations):
    refuse()
names = sorted(path.name for path in operations)
claims = entries(client / "credentials")
if len(claims) > 1 or any(not path.is_dir() or not re.fullmatch(space + r"-[0-9a-f]{64}", path.name) for path in claims):
    refuse()
if mode == "begin":
    state = {"before": names, "operation": None, "claim": None, "claim_files": {}, "files": {}}
else:
    state = json.loads(state_file.read_text())
    if state["operation"] is None:
        added = set(names) - set(state["before"])
        if mode != "bind" or len(added) != 1 or set(state["before"]) - set(names):
            refuse()
        state["operation"] = added.pop()
        credential = state["operation"].split("-")[0]
        if len(claims) != 1 or claims[0].name != f"{space}-{credential}":
            refuse()
        state["claim"] = claims[0].name
        state["claim_files"] = files(claims[0])
        if not state["claim_files"] or not any(name.startswith("credential.reservation") for name in state["claim_files"]):
            refuse()
    if names != sorted(state["before"] + [state["operation"]]) or len(claims) != 1 or claims[0].name != state["claim"]:
        refuse()
    claim_files = files(claims[0])
    if mode != "success" and claim_files != state["claim_files"]:
        refuse()
    current = files(client / "operations" / state["operation"])
    if any(current.get(name) != value for name, value in state["files"].items()):
        refuse()
    other_requests = {"local-create.request", "local-install.request", "shared-create.request", "shared-install.request"} - {request_name}
    if any(Path(name).name in other_requests for name in current):
        refuse()
    if f"request/{request_name}" not in current and "query/credential.query" not in current:
        refuse()
    state["files"] = current
    if mode == "success":
        state["claim_files"] = claim_files
state_file.write_text(json.dumps(state, sort_keys=True) + "\n")
PY
}
lifecycle_retryable() {
    python3 - "$1" <<'PY'
import json, re, sys
from pathlib import Path
try:
    error = json.loads(Path(sys.argv[1]).read_text().splitlines()[-1])
    if not isinstance(error, dict):
        raise TypeError()
    message = error["error"]
except (OSError, IndexError, KeyError, ValueError, TypeError):
    raise SystemExit(1)
if error.get("code") != 1 or not isinstance(message, str):
    raise SystemExit(1)
if re.search(r"signed denial|verified terminal|denied;|invalid |malformed|corrupt|oversized", message, re.I):
    raise SystemExit(1)
status = re.search(r"\bstatus code (\d{3})\b", message)
if status:
    raise SystemExit(0 if status[1] in {"409", "429", "503", "504"} else 1)
transport = re.search(r"network error|connection failed|connection refused|connection reset|timed out|timeout|unexpected end of file|broken pipe", message, re.I)
retained = re.search(r"request retained|retry the identical retained credential query", message, re.I)
loopback = re.search(r"http://127\.0\.0\.1:\d+(?:/|:)", message)
raise SystemExit(0 if transport and (retained or loopback) else 1)
PY
}
run_lifecycle() {
    local step=$1 persona=$2 started clock_start deadline now attempt=0 code=0 duration attempt_started attempt_clock remaining
    local -a resume=()
    shift 2
    clock_start=$(monotonic_ms); started=$(date +%s%3N); deadline=$((clock_start + 180000))
    lifecycle_fence begin "$persona" "$step"
    while true; do
        now=$(monotonic_ms); remaining=$((deadline - now))
        # Keep the existing ten-second CLI termination grace inside the whole
        # step bound. Every attempt uses only the remaining budget.
        (( remaining > 10000 )) || fail "$step has no CLI budget left within its existing 180s command bound; inspect retained attempts"
        if (( attempt > 0 )); then lifecycle_fence verify "$persona" "$step"; fi
        now=$(monotonic_ms); remaining=$((deadline - now - 10000))
        (( remaining > 0 )) || fail "$step has no CLI budget left within its existing 180s command bound; inspect retained attempts"
        printf -v duration '%d.%03ds' "$((remaining / 1000))" "$((remaining % 1000))"
        ((attempt+=1)); code=0; attempt_started=$(date +%s%3N); attempt_clock=$(monotonic_ms)
        cli_bounded "$persona" "$duration" "$@" "${resume[@]}" > "$evidence/logs/$step.attempt-$attempt.stdout" 2> "$evidence/logs/$step.attempt-$attempt.stderr" || code=$?
        now=$(monotonic_ms)
        printf '%s.attempt-%s\t%s\t%s\t%s\n' "$step" "$attempt" "$attempt_started" "$((now - attempt_clock))" "$code" >> "$evidence/timings.tsv"
        install -m 0600 -- "$evidence/logs/$step.attempt-$attempt.stdout" "$evidence/logs/$step.stdout"
        install -m 0600 -- "$evidence/logs/$step.attempt-$attempt.stderr" "$evidence/logs/$step.stderr"
        (( now < deadline )) || fail "$step exceeded its existing 180s command bound; inspect retained attempts"
        if (( code == 0 )); then
            if (( attempt > 1 )); then lifecycle_fence success "$persona" "$step"; fi
            now=$(monotonic_ms)
            printf '%s\t%s\t%s\t0\n' "$step" "$started" "$((now - clock_start))" >> "$evidence/timings.tsv"
            (( now < deadline )) || fail "$step completed after its existing 180s command bound"
            return
        fi
        if (( code != 1 )) || ! lifecycle_retryable "$evidence/logs/$step.stderr"; then
            printf '%s\t%s\t%s\t%s\n' "$step" "$started" "$((now - clock_start))" "$code" >> "$evidence/timings.tsv"
            fail "$step failed ($code) without a retryable retained transport outcome; inspect retained logs"
        fi
        lifecycle_fence bind "$persona" "$step"
        resume=(--resume)
        sleep 0.1
    done
}
stop_all() {
    local pid index deadline code=0 status started
    local -a remaining_pids=() remaining_starts=()
    (( ${#pids[@]} > 0 )) || return 0
    started=$(date +%s%3N)
    for index in "${!pids[@]}"; do
        pid=${pids[index]}
        if owned_live "$pid" "${pid_starts[index]}"; then kill -TERM "$pid" 2>/dev/null || true; fi
    done
    deadline=$((SECONDS + 30))
    for index in "${!pids[@]}"; do
        pid=${pids[index]}
        while owned_live "$pid" "${pid_starts[index]}" && (( SECONDS < deadline )); do sleep 0.1; done
        if owned_live "$pid" "${pid_starts[index]}"; then
            echo "owned daemon $pid did not stop gracefully; no forced kill; evidence preserved" >&2
            printf '%s\n' "$pid" >> "$evidence/still-running-owned-pids.txt"
            remaining_pids+=("$pid"); remaining_starts+=("${pid_starts[index]}")
            code=1
        else
            status=0; wait "$pid" || status=$?
            (( status == 0 )) || code=1
        fi
    done
    printf 'graceful-stop\t%s\t%s\t%s\n' "$started" "$(( $(date +%s%3N) - started ))" "$code" >> "$evidence/timings.tsv"
    # Prune reaped/exited entries even when another owned daemon did not stop.
    pids=("${remaining_pids[@]}"); pid_starts=("${remaining_starts[@]}")
    return "$code"
}
cleanup() { local code=$?; trap - EXIT; stop_all || code=1; exit "$code"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
for persona in a b c; do mkdir -p -- "$evidence/$persona/config/vosx" "$evidence/$persona/data" "$evidence/$persona/cache"; done
run release-verify a release verify "$release_source"
run frozen-release-verify a release verify "$evidence/release"
jq -r 'to_entries[] | select(.value | type == "object") | [.key,.value.program_id,.value.blake2b_256] | @tsv' "$evidence/release/manifest.json" > "$evidence/roles.tsv"
run cli-schema a help-schema
run new a space new "$name" --data-dir "$evidence/a/space"
space_id=$(jq -er '.space_id | select(test("^[0-9a-f]{64}$"))' "$evidence/logs/new.stdout")
peers=("$(jq -er '.peer_id' "$evidence/logs/new.stdout")")
run root-public-identity a whoami --json
root_peer=$(jq -er '.peer_id' "$evidence/logs/root-public-identity.stdout")
run registry-only-backup a space backup "$name" "$evidence/registry-seed"
for persona in b c; do
    # This source is the newly generated test Root, never an ambient operator key.
    install -m 0600 -- "$evidence/a/config/vosx/identity.key" "$evidence/$persona/config/vosx/identity.key"
    run "prepare-$persona" "$persona" space prepare-bootstrap-member "$name" "$evidence/registry-seed" \
        --space-id "$space_id" --root-peer-id "$root_peer" --data-dir "$evidence/$persona/space"
    peer=$(sed -n 's/^Prepared .* with fresh node \([^ ]*\)\. No System Agent.*$/\1/p' "$evidence/logs/prepare-$persona.stdout")
    [[ $peer =~ ^12D3KooW[A-Za-z0-9]+$ ]] || fail "could not retain member PeerId"
    peers+=("$peer")
done
[[ ${peers[0]} != "${peers[1]}" && ${peers[0]} != "${peers[2]}" && ${peers[1]} != "${peers[2]}" ]] || fail "node identities are not distinct"
for persona in a b c; do run "enrollment-$persona" "$persona" space export-bootstrap-enrollment "$name" "$evidence/enrollments/$persona.nen"; done
run common-bootstrap a space prepare-common-bootstrap "$name" "$evidence/common-bootstrap" \
    --enrollment "$evidence/enrollments/a.nen" --enrollment "$evidence/enrollments/b.nen" --enrollment "$evidence/enrollments/c.nen"
index=0
for persona in a b c; do
    printf 'local_agent_storage = "image"\nsystem_bootstrap_bundle = "%s"\n[[ingress.http]]\nname = "http"\nlisten = "127.0.0.1:%s"\n[[ingress.ssh]]\nname = "ssh"\nlisten = "127.0.0.1:%s"\n' \
        "$evidence/common-bootstrap/common.bundle" "$((base_port+3+index))" "$((base_port+6+index))" > "$evidence/$persona/space/local.toml"
    ((index+=1))
done
start_all() {
    local phase=$1 index=0 persona peer_index started deadline pid identity status
    (( ${#pids[@]} == 0 )) || fail "cannot restart beside a still-live owned daemon"
    started=$(date +%s%3N)
    for persona in a b c; do
        connects=()
        for peer_index in 0 1 2; do
            if (( peer_index != index )); then connects+=(--connect "/ip4/127.0.0.1/tcp/$((base_port+peer_index))/p2p/${peers[peer_index]}"); fi
        done
        env XDG_DATA_HOME="$evidence/$persona/data" XDG_CONFIG_HOME="$evidence/$persona/config" \
            XDG_CACHE_HOME="$evidence/$persona/cache" TMPDIR="$evidence/tmp" VOSX_DISABLE_MDNS=1 RUST_LOG=info \
            "$binary" --format json space up "$name" --listen "/ip4/127.0.0.1/tcp/$((base_port+index))" "${connects[@]}" \
            > "$evidence/logs/$phase-$persona.stdout" 2> "$evidence/logs/$phase-$persona.stderr" &
        pid=$!
        if ! identity=$(process_identity "$pid"); then
            status=0; wait "$pid" || status=$?
            fail "$phase persona $persona exited before launch identity capture (status $status)"
        fi
        pids+=("$pid"); pid_starts+=("${identity%% *}")
        printf '%s\t%s\t%s\t%s\n' "$phase" "$persona" "$pid" "${identity%% *}" >> "$evidence/daemon-pids.tsv"
        ((index+=1))
    done
    # Observation cap only; timings retain actual wall time, not a service SLO.
    deadline=$((SECONDS + 180)); index=0
    for persona in a b c; do
        pid=${pids[index]}
        until owned_live "$pid" "${pid_starts[index]}" \
            && [[ -f $evidence/$persona/space/.endpoint && ! -L $evidence/$persona/space/.endpoint ]] \
            && [[ $(awk '$1 == "pid" && $2 == "=" {print $3}' "$evidence/$persona/space/.endpoint") == "$pid" ]] \
            && [[ $(sed -n 's/^peer_id = "\([^"]*\)"$/\1/p' "$evidence/$persona/space/.endpoint") == "${peers[index]}" ]] \
            && curl --noproxy '*' --fail --silent --max-time 2 "http://127.0.0.1:$((base_port+3+index))/__status" \
            > "$evidence/logs/$phase-$persona-status.json" && jq -e '.status == "ok"' "$evidence/logs/$phase-$persona-status.json" >/dev/null; do
            owned_live "$pid" "${pid_starts[index]}" || fail "$phase persona $persona daemon exited or launch identity changed"
            (( SECONDS < deadline )) || fail "$phase three-process readiness observation exceeded 180s"
            sleep 0.1
        done
        ((index+=1))
    done
    printf '%s-ready\t%s\t%s\t0\n' "$phase" "$started" "$(( $(date +%s%3N) - started ))" >> "$evidence/timings.tsv"
}
query() {
    local step=$1 persona=$2 agent=$3 port=$4
    run "$step" "$persona" space call-agent-actor "$name" "$agent" clerk-ledger journal_id --package "$clerk" --args '{}' --http "127.0.0.1:$port"
    jq -e '.decision == "issued" and .delivery_retired == true and .result.status == "Done" and .result.value == "0x"' "$evidence/logs/$step.stdout" >/dev/null || fail "$step did not complete the actual empty Clerk query/ACK"
}
start_all first
run_lifecycle local-create a space create-local-agent "$name" --http "127.0.0.1:$((base_port+3))"
local_agent=$(jq -er '.agent | select(test("^[0-9a-f]{64}$"))' "$evidence/logs/local-create.stdout")
run_lifecycle local-install a space install-local-actor "$name" "$local_agent" "$clerk" --http "127.0.0.1:$((base_port+3))"
query local-query a "$local_agent" "$((base_port+3))"
run_lifecycle shared-create a space create-shared-agent "$name" --runtime "$evidence/release/shared-external-runtime.vos" \
    --enrollment "$evidence/enrollments/a.nen" --enrollment "$evidence/enrollments/b.nen" --enrollment "$evidence/enrollments/c.nen" \
    --archive-out "$evidence/shared.ogar" --http "127.0.0.1:$((base_port+3))"
jq -e '.phase == "applied" and .ready == false and .management_completed == true and .response_retained == true' "$evidence/logs/shared-create.stdout" >/dev/null || fail "Shared Create did not retain Applied"
shared_agent=$(jq -er '.agent | select(test("^[0-9a-f]{64}$"))' "$evidence/logs/shared-create.stdout")
index=0
for persona in a b c; do
    run "admit-$persona" "$persona" space admit-shared "$name" --archive "$evidence/shared.ogar" --http "127.0.0.1:$((base_port+3+index))"
    ((index+=1))
done
run_lifecycle shared-install a space install-shared-actor "$name" "$shared_agent" "$clerk" --http "127.0.0.1:$((base_port+3))"
jq -e '.decision == "applied" and .management_completed == true and .response_retained == true' "$evidence/logs/shared-install.stdout" >/dev/null || fail "Shared Install did not retain Applied"
for phase in before-reopen after-reopen; do
    if [[ $phase == after-reopen ]]; then stop_all; start_all reopened; query reopened-local a "$local_agent" "$((base_port+3))"; fi
    index=0
    for persona in a b c; do query "$phase-shared-$persona" "$persona" "$shared_agent" "$((base_port+3+index))"; ((index+=1)); done
done
stop_all
sha256sum --check --status "$evidence/artifacts.sha256" || fail "frozen artifact identity changed"
printf '%s\n' 'PASS: direct packaged CLI offline preparation, three live processes, Local/Shared lifecycle and empty public Clerk queries/ACK, graceful all-owner reopen.' >> "$evidence/acceptance.txt"
echo "bounded CLI slice passed; OPEN acceptance remains in $evidence/acceptance.txt"
