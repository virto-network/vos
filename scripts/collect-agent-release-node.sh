#!/usr/bin/env bash
# Read-only node observations for the approved fixed-three acceptance envelope.
# This does not deploy, provision credentials, run load, or qualify the release.
# Run on each supplied node with the exact independently retained release hash.
# Supplying peer addresses requires ping and Python3's standard-library ipaddress.
set -euo pipefail
umask 077

if (( $# < 3 )); then
    echo "usage: bash $0 VOSX EXPECTED_SHA256 DISK_EVIDENCE_ROOT [PEER_IP ...]" >&2
    exit 2
fi
for command in realpath sha256sum stat mktemp date uname getconf nproc awk timeout; do
    command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 2; }
done
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
    echo 'This release envelope supports Linux x86-64 only' >&2; exit 2;
}
binary=$(realpath -- "$1")
expected=$2
evidence_root=$3
shift 3
[[ -f $binary && -x $binary && $expected =~ ^[0-9a-f]{64}$ ]] || {
    echo 'Require an executable release binary and canonical SHA-256' >&2; exit 2;
}
if (( $# > 0 )); then
    for command in python3 ping; do
        command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 2; }
    done
fi
for peer in "$@"; do
    # Standard-library numeric parsing never resolves DNS. A hex-only hostname
    # must not pass just because it uses IPv6's character alphabet.
    python3 -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$peer" \
        >/dev/null 2>&1 || {
        echo 'Peers must be literal IPv4/IPv6 addresses, not options or hostnames' >&2; exit 2;
    }
done
digest=$(sha256sum -- "$binary")
[[ ${digest%% *} == "$expected" ]] || {
    echo 'Release binary hash differs from the independently retained hash' >&2; exit 1;
}
mkdir -p -- "$evidence_root"
evidence_root=$(realpath -- "$evidence_root")
case $(stat -f -c %T -- "$evidence_root") in
    tmpfs|ramfs) echo 'Require disk-backed evidence storage, not RAM-backed storage' >&2; exit 2 ;;
esac
evidence=$(mktemp -d "$evidence_root/node.XXXXXX")
mkdir -- "$evidence/tmp"
export TMPDIR="$evidence/tmp"
printf '%s\n' "$digest" > "$evidence/binary.sha256"
sha256sum -- "${BASH_SOURCE[0]}" > "$evidence/collector.sha256"
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$evidence/observed-at.txt"
uname -srmo > "$evidence/platform.txt"
timeout 5 "$binary" --version > "$evidence/binary-version.txt" 2>&1
IFS= read -r version_line < "$evidence/binary-version.txt"
[[ $version_line == 'vosx '* ]] || { echo 'Supplied executable is not vosx' >&2; exit 2; }
{
    printf 'online_cpus=%s\n' "$(getconf _NPROCESSORS_ONLN)"
    printf 'available_cpus=%s\n' "$(nproc)"
    awk '/^(MemTotal|MemAvailable|SwapTotal|SwapFree):/ {print}' /proc/meminfo
} > "$evidence/resources.txt"
stat -f -c 'filesystem=%T block_size=%S available_blocks=%a' -- "$evidence" \
    > "$evidence/disk.txt"
if command -v findmnt >/dev/null; then
    findmnt -T "$evidence" -n -o SOURCE,FSTYPE,OPTIONS > "$evidence/mount.txt"
    mount_source=$(findmnt -T "$evidence" -n -o SOURCE)
    if command -v lsblk >/dev/null && [[ -b $mount_source ]]; then
        lsblk -s -n -o NAME,TYPE,ROTA,SIZE -- "$mount_source" > "$evidence/block-devices.txt"
    fi
fi
if command -v timedatectl >/dev/null; then
    timeout 5 timedatectl show -p NTPSynchronized -p TimeUSec \
        > "$evidence/clock.txt" 2>&1 || true
fi
peer_index=0
for peer in "$@"; do
    peer_index=$((peer_index + 1))
    printf '%s\n' "$peer" > "$evidence/peer-$peer_index.txt"
    # Packet loss, permission failure and RTT remain evidence, never a pass.
    ping -n -c 10 -i 0.2 -W 1 -- "$peer" \
        > "$evidence/peer-$peer_index-ping.txt" 2>&1 || true
done
after=$(sha256sum -- "$binary")
[[ $after == "$digest" ]] || { echo 'Binary changed during collection' >&2; exit 1; }
printf '%s\n' \
    'hardware_qualification=OPEN' \
    'required_nodes=3 Linux x86-64' \
    'required_per_node=8 vCPU, 16 GiB RAM, SSD' \
    'required_peer_RTT_ms<=5' \
    'required_active_clients=300; read_mutation_mix=80/20' \
    'required_end_to_end_latency_ms=p95<=1000,p99<=2000 including queues/retries' \
    'required_workload=1000 accounts,100000 retained distinct-external-ID transfers' \
    'required_load_seconds=1800; retention_soak_seconds=86400' \
    'required_failover_seconds<=30; correctness and backup/restore gates unchanged' \
    'observations_only=No deployment, load, recovery, SSD capacity or service claim' \
    > "$evidence/qualification.txt"
printf 'Node observations: %s\nHardware/load/recovery qualification remains OPEN.\n' "$evidence"
