#!/usr/bin/env bash
# Disposable Local/Public-policy qualification, not production/load acceptance.
# Build the CLI and its test client first. This script freezes both inputs.
set -euo pipefail

if (( $# < 3 || $# > 4 )); then
    echo "usage: $0 VOSX TEST_CLIENT COUNTER_PACKAGE [DISK_EVIDENCE_ROOT]" >&2
    exit 2
fi
for command in git rg realpath mktemp stat sha256sum ss curl jq ssh-keyscan timeout awk getconf; do
    command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 2; }
done
binary_source=$(realpath "$1")
client_source=$(realpath "$2")
counter_source=$(realpath "$3")
if [[ ! -x $binary_source || ! -x $client_source || ! -s $counter_source ]]; then
    echo 'Require executable CLI/test-client and a nonempty Counter package' >&2
    exit 2
fi
repository_root=$(git rev-parse --show-toplevel)
evidence_root=${4:-"$repository_root/target/agent-lifecycle-qualification"}
mkdir -p "$evidence_root"
evidence_root=$(realpath "$evidence_root")
case $(stat -f -c %T "$evidence_root") in
    tmpfs|ramfs) echo 'Use disk-backed evidence storage, not RAM-backed storage' >&2; exit 2 ;;
esac
evidence=$(mktemp -d "$evidence_root/indexed-lifecycle.XXXXXX")
echo "qualification evidence: $evidence"
cp "$binary_source" "$evidence/qualified-vosx"
cp "$client_source" "$evidence/qualified-test-client"
cp "$counter_source" "$evidence/counter.vos"
cp "${BASH_SOURCE[0]}" "$evidence/qualification.sh"
binary="$evidence/qualified-vosx"
test_binary="$evidence/qualified-test-client"
sha256sum "$binary" "$test_binary" "$evidence/counter.vos" "$evidence/qualification.sh" > "$evidence/identities.sha256"
git rev-parse HEAD > "$evidence/source-revision.txt"
git status --short > "$evidence/source-status.txt"
uname -srmo > "$evidence/platform.txt"
getconf CLK_TCK > "$evidence/cpu-clock-ticks-per-second.txt"
mkdir "$evidence/tmp"
export TMPDIR="$evidence/tmp" XDG_DATA_HOME="$evidence/data"
export XDG_CONFIG_HOME="$evidence/config" XDG_CACHE_HOME="$evidence/cache"
export VOSX_DISABLE_MDNS=1 VOSX_INVOKE_SMOKE_SPACE=indexed-lifecycle
export VOSX_INVOKE_SMOKE_CONFIG="$evidence/create.txt"
export RUST_LOG=info,vosx::commands::space::clean_startup=debug,vos::agent::production_owner=debug,vos::agent::clean_bootstrap=debug
probe_pid=''
sampler_pid=''
cleanup() {
    if [[ -n $sampler_pid ]]; then
        kill -TERM "$sampler_pid" 2>/dev/null || true
        wait "$sampler_pid" 2>/dev/null || true
    fi
    if [[ -n $probe_pid ]]; then
        kill -TERM "$probe_pid" 2>/dev/null || true
        for attempt in {1..50}; do
            kill -0 "$probe_pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$probe_pid" 2>/dev/null; then
            echo "forced cleanup of qualification child $probe_pid" >&2
            kill -KILL "$probe_pid" 2>/dev/null || true
        fi
        wait "$probe_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
listeners=$(ss -H -ltn)
if awk '{print $4}' <<< "$listeners" | rg -q ':(18109|2253)$'; then
    echo 'Disposable qualification ports are occupied' >&2
    exit 1
fi

record_duration() {
    local phase=$1 started=$2
    printf '%s\t%s\n' "$phase" "$(( $(date +%s%3N) - started ))" >> "$evidence/timings-ms.tsv"
}
sample_process() {
    local pid=$1
    # This background sampler must never run the parent daemon cleanup trap.
    trap - EXIT INT TERM HUP
    while kill -0 "$pid" 2>/dev/null; do
        # Samples, not guaranteed peaks. CPU uses kernel ticks; RSS is KiB.
        printf 'timestamp_ms=%s\n' "$(date +%s%3N)"
        awk '/^(VmRSS|VmHWM|Threads):/ {print}' "/proc/$pid/status" || break
        awk '{print "user_ticks=" $14, "system_ticks=" $15}' "/proc/$pid/stat" || break
        local fds=(/proc/"$pid"/fd/*)
        printf 'fd_count=%s\n' "${#fds[@]}"
        sleep 1
    done
}
start_daemon() {
    local phase=$1 started deadline
    started=$(date +%s%3N)
    "$binary" space up indexed-lifecycle > "$evidence/$phase.log" 2>&1 &
    probe_pid=$!
    sample_process "$probe_pid" > "$evidence/$phase.resources" 2>&1 &
    sampler_pid=$!
    deadline=$((SECONDS + 180))
    until rg -q 'Space daemon ready' "$evidence/$phase.log"; do
        if ! kill -0 "$probe_pid" 2>/dev/null; then wait "$probe_pid"; return 1; fi
        if (( SECONDS >= deadline )); then echo 'Readiness exceeded observation bound' >&2; return 1; fi
        sleep 0.1
    done
    record_duration "$phase-readiness" "$started"
    curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18109/__status | jq -e '.status == "ok"'
}
stop_daemon() {
    local phase=$1 started deadline
    started=$(date +%s%3N)
    kill -TERM "$probe_pid"
    deadline=$((SECONDS + 5))
    while kill -0 "$probe_pid" 2>/dev/null; do
        if (( SECONDS >= deadline )); then echo 'Shutdown exceeded 5s' >&2; return 1; fi
        sleep 0.1
    done
    wait "$probe_pid"
    probe_pid=''
    kill -TERM "$sampler_pid" 2>/dev/null || true
    wait "$sampler_pid" 2>/dev/null || true
    sampler_pid=''
    record_duration "$phase-shutdown" "$started"
}
run_test() {
    local name=$1 phase=$2 started
    started=$(date +%s%3N)
    timeout --signal=TERM --kill-after=5s 180s "$test_binary" \
        "commands::space::local_operation::live_tests::$name" \
        --exact --ignored --nocapture --test-threads=1 > "$evidence/$phase-test.log" 2>&1
    # Rust's harness exits zero if a stale binary contains no matching test.
    rg -q '^test result: ok\. 1 passed; 0 failed;' "$evidence/$phase-test.log"
    record_duration "$phase-test" "$started"
}

"$binary" release bundle --out "$evidence/bundle" > "$evidence/bundle.log" 2>&1
"$binary" release verify "$evidence/bundle" >> "$evidence/bundle.log" 2>&1
"$binary" space new indexed-lifecycle --data-dir "$evidence/space" > "$evidence/new.log" 2>&1
cp "$evidence/space/local.toml" "$evidence/generated-local.toml"
# Require enabled default ingress, then change only the two disposable ports.
rg -q '^listen = "127.0.0.1:8080"$' "$evidence/generated-local.toml"
rg -q '^listen = "127.0.0.1:2222"$' "$evidence/generated-local.toml"
sed -i 's/127\.0\.0\.1:8080/127.0.0.1:18109/; s/127\.0\.0\.1:2222/127.0.0.1:2253/' "$evidence/space/local.toml"
start_daemon initial
ssh-keyscan -T 5 -p 2253 127.0.0.1 > "$evidence/ssh-key.txt" 2> "$evidence/ssh.stderr"
started=$(date +%s%3N)
timeout --signal=TERM --kill-after=5s 180s "$binary" space create-local-agent indexed-lifecycle > "$evidence/create.txt" 2> "$evidence/create.stderr"
record_duration create "$started"
agent_id=$(sed -nE 's/^Local Agent ([0-9a-f]{64}): verified creation acknowledgement$/\1/p' "$evidence/create.txt")
[[ $agent_id =~ ^[0-9a-f]{64}$ ]]
started=$(date +%s%3N)
timeout --signal=TERM --kill-after=5s 180s "$binary" space install-local-actor indexed-lifecycle "$agent_id" "$evidence/counter.vos" --name counter > "$evidence/install.txt" 2> "$evidence/install.stderr"
record_duration install "$started"
stop_daemon initial
start_daemon restart
stop_daemon restart
start_daemon mutation
run_test real_daemon_counter_mutation_and_exact_retry mutation
stop_daemon mutation
start_daemon read
run_test real_daemon_counter_value_after_restart read
stop_daemon read
sha256sum --check "$evidence/identities.sha256"
{
    printf 'phase\tsampled_rss_kib\treported_hwm_kib\tsampled_threads\tsampled_fds\tlast_cpu_ticks\n'
    for phase in initial restart mutation read; do
        awk -v phase="$phase" '
            /^VmRSS:/ {if ($2 > rss) rss=$2}
            /^VmHWM:/ {if ($2 > hwm) hwm=$2}
            /^Threads:/ {if ($2 > threads) threads=$2}
            /^fd_count=/ {split($0,a,"="); if(a[2] > fds) fds=a[2]}
            /^user_ticks=/ {split($1,u,"="); split($2,s,"="); ticks=u[2]+s[2]}
            END {printf "%s\t%d\t%d\t%d\t%d\t%d\n",phase,rss,hwm,threads,fds,ticks}
        ' "$evidence/$phase.resources"
    done
} > "$evidence/resources-summary.tsv"
echo 'PASS Local/Public functional lifecycle; not full release or load qualification'
if awk '$1 ~ /-readiness$/ && $2 > 10000 {failed=1} END {exit !failed}' "$evidence/timings-ms.tsv"; then
    echo 'FAIL production readiness gate: at least one startup exceeded 10000 ms'
    exit 1
fi
echo 'PASS scoped 10000 ms readiness gate; throughput and other release gates remain open'
