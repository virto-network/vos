#!/usr/bin/env bash
# The process bench's rows on a machine of its own, each node on physical
# cores of its own (one thread a core where there are cores enough, the
# siblings left idle), the driver on further cores: what the laptop's
# shared, hyperthreaded pinning cannot show. Run from anywhere in the
# checkout:
#
#   node/cli/benches/machine.sh [--plan] [--cpus LIST] [--data DIR]
#                               [--memory SIZE|none] [--soak]
#
#   --plan         describe the machine and the pinning it would use, and
#                  stop: run this first.
#   --cpus LIST    the CPUs the runs may use, as ranges and lists
#                  (`16-31,48-63`; default: every online CPU). Only cores
#                  whose threads are
#                  all listed are used. On a machine with another service,
#                  list the cores left to the bench, and pin that service
#                  to the others (for a systemd service, `CPUAffinity=`):
#                  leaving its CPUs out does not keep it off the bench's.
#   --data DIR     a directory on the disk to measure: the rows run in
#                  `DIR/vos-bench` as well as on tmpfs (`/dev/shm`). Not on
#                  another service's database disk: the rows sync it
#                  constantly.
#   --memory SIZE  the cap on everything it runs, builds included, through
#                  `systemd-run --user` (default 24G). It refuses to run
#                  when the cap cannot be enforced, unless given `none`, and
#                  when the cap is above three quarters of the memory
#                  available, which would squeeze other services first.
#   --soak         also the 64 agents' 15-minute soak, on tmpfs.
#
# Builds the agent, the test actors and the benches, then runs: the
# in-process bench (one node: refine and dry run an input); one agent and
# the quiet, query (applied and linearizable) and idle rows, then a
# failover of the idle agents; one agent with its sessions spread over
# the nodes; the 64 agents, closed and open, and their knee, then a
# failover under them. Everything
# goes into `bench-<host>-<time>/` in the directory it is run from, with
# the machine's description and a summary, and into a `.tar.gz` of it to
# send back. It takes about an hour, more with `--data`, and longer the
# first time, which builds everything.
#
# Needs: Linux 6.7 or later (the JIT's write tracking), `rustup` (the
# toolchains are pinned in the checkout), `taskset`, `python3`, `lscpu`.
set -euo pipefail

# Results go where it is run; it builds and runs in the checkout.
here="$(pwd)"
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"

allowed=""
disk=""
memory="24G"
soak=0
plan=0
usage() { echo "$1 (see --help)" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --cpus | --data | --memory) [ $# -ge 2 ] || usage "$1 needs a value" ;;
  esac
  case "$1" in
    --cpus) allowed="$2"; shift 2 ;;
    --data) disk="$2"; shift 2 ;;
    --memory) memory="$2"; shift 2 ;;
    --soak) soak=1; shift ;;
    --plan) plan=1; shift ;;
    -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
    *) usage "unknown argument: $1" ;;
  esac
done

name="bench-$(hostname -s)-$(date +%Y%m%d-%H%M%S)"
out="$here/$name"
mkdir -p "$out"
note() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$out/progress.txt"; }

# --- The requirements -------------------------------------------------------
for tool in cargo rustup taskset python3 lscpu; do
  command -v "$tool" > /dev/null || { echo "$tool is missing" >&2; exit 1; }
done
read -r major minor < <(uname -r | sed 's/^\([0-9]*\)\.\([0-9]*\).*/\1 \2/')
if [ "$major" -lt 6 ] || { [ "$major" -eq 6 ] && [ "$minor" -lt 7 ]; }; then
  echo "Linux $(uname -r): the node needs 6.7 or later" >&2
  exit 1
fi
[ -z "$allowed" ] && allowed="$(lscpu -p=CPU | grep -v '^#' | paste -sd,)"
if [ -n "$disk" ]; then
  mkdir -p "$disk/vos-bench"
  disk="$(cd "$disk/vos-bench" && pwd)"
fi

# --- The memory cap ------------------------------------------------------------
# A scope's MemoryMax holds only where the user's manager has the memory
# controller: a scope that starts proves nothing.
scope=0
if [ "$memory" != none ]; then
  controllers="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers"
  if ! systemd-run --user --scope -q true 2> /dev/null; then
    echo "systemd-run --user does not work here, so the memory cap cannot be set: give --memory none to run without it" >&2
    exit 1
  fi
  if ! grep -qw memory "$controllers" 2> /dev/null; then
    echo "the user's systemd manager has no memory controller ($controllers), so the cap would not hold: give --memory none to run without it" >&2
    exit 1
  fi
  available=$(awk '/^MemAvailable:/ { print $2 * 1024 }' /proc/meminfo)
  cap=$(numfmt --from=iec "$memory")
  if [ "$cap" -gt $((available / 4 * 3)) ]; then
    echo "a cap of $memory is above three quarters of the $(numfmt --to=iec "$available") available: give a smaller --memory" >&2
    exit 1
  fi
  scope=1
fi
# Each run in a scope of its own, named so that the cleanup can stop what
# a killed run leaves behind (its nodes, if the bench itself was killed).
scoped() {
  if [ "$scope" = 1 ]; then
    systemd-run --user --scope -q --unit="vos-bench-$$-$(date +%s%N)" \
      -p "MemoryMax=$memory" -p MemorySwapMax=0 "$@"
  else
    "$@"
  fi
}

# --- The machine --------------------------------------------------------------
{
  echo "== vos-core $(git rev-parse --short HEAD) ($(git status --porcelain | wc -l) uncommitted)"
  echo "== uname"; uname -a
  echo "== lscpu"; lscpu
  echo "== lscpu -e"; lscpu -e
  echo "== caches"; lscpu -C 2> /dev/null || true
  for kind in cpu_core cpu_atom; do
    if [ -r "/sys/devices/$kind/cpus" ]; then echo "== $kind: $(cat "/sys/devices/$kind/cpus")"; fi
  done
  echo "== governor"; cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2> /dev/null || echo unknown
  if command -v numactl > /dev/null; then echo "== numactl -H"; numactl -H; fi
  echo "== memory"; free -g
  echo "== disks"; lsblk -o NAME,MODEL,SIZE,ROTA,TYPE,MOUNTPOINTS 2> /dev/null || lsblk
  echo "== /dev/shm"; findmnt -T /dev/shm
  if [ -n "$disk" ]; then echo "== $disk"; findmnt -T "$disk"; df -h "$disk"; fi
  echo "== transparent huge pages"; cat /sys/kernel/mm/transparent_hugepage/enabled
  echo "== ephemeral ports"; cat /proc/sys/net/ipv4/ip_local_port_range
  echo "== allowed CPUs"; echo "$allowed"
  echo "== memory cap"; echo "$memory"
} > "$out/machine.txt" 2>&1

# --- The pinning --------------------------------------------------------------
# Whole physical cores among the allowed CPUs, by NUMA node, socket and
# core; on a hybrid CPU, only its performance cores for the nodes. Each
# node takes K cores, one thread of each, within one NUMA node where it
# fits; with too few cores for three a node, both threads of two or more.
# The driver takes further cores, both threads.
pinning="$(python3 - "$allowed" 2> "$out/pinning.txt" << 'EOF'
import os, subprocess, sys

def expand(spec):
    cpus = set()
    for part in spec.split(','):
        part = part.strip()
        if '-' in part:
            low, high = part.split('-')
            cpus.update(range(int(low), int(high) + 1))
        elif part:
            cpus.add(int(part))
    return cpus

allowed = expand(sys.argv[1])
efficient = set()
if os.path.exists('/sys/devices/cpu_atom/cpus'):
    efficient = expand(open('/sys/devices/cpu_atom/cpus').read().strip())
threads = {}
listing = subprocess.check_output(['lscpu', '-p=CPU,CORE,SOCKET,NODE'], text=True)
for line in listing.splitlines():
    if line.startswith('#'):
        continue
    cpu, core, socket, node = (int(field or 0) for field in line.split(','))
    threads.setdefault((node, socket, core), []).append(cpu)
whole = {key: sorted(cpus) for key, cpus in threads.items() if set(cpus) <= allowed}
partial = [key for key, cpus in threads.items() if set(cpus) & allowed and not set(cpus) <= allowed]
fast = sorted(key for key in whole if not set(whole[key]) & efficient)
slow = sorted(key for key in whole if set(whole[key]) & efficient)
notes = []
if partial:
    notes.append(f'{len(partial)} cores only partly allowed, not used')
if slow:
    notes.append(f'{len(slow)} efficiency cores, the driver\'s only')

driver_cores = min(8, max(4, len(whole) // 6))
spare = len(fast) - max(0, driver_cores - len(slow))
each, both = min(8, spare // 3), False
if each < 3:
    # Too few cores for three a node on one thread each: both threads.
    each, both = min(4, spare // 3), True
    notes.append('cores scarce: each node on both threads of its cores')
if each < 2:
    sys.exit(f'{len(fast)} whole performance cores allowed: the three nodes need at least two each, and the driver four more')

def take(pool, count):
    # Within one NUMA node where it fits.
    by_numa = {}
    for key in pool:
        by_numa.setdefault(key[0], []).append(key)
    for numa in sorted(by_numa):
        if len(by_numa[numa]) >= count:
            chosen = by_numa[numa][:count]
            break
    else:
        chosen = pool[:count]
        notes.append('a node straddles NUMA nodes')
    for key in chosen:
        pool.remove(key)
    return chosen

pool = list(fast)
nodes = []
for _ in range(3):
    cores = take(pool, each)
    nodes.append([cpu for key in cores for cpu in (whole[key] if both else whole[key][:1])])
driver = [cpu for key in (slow + pool)[:driver_cores] for cpu in whole[key]]
print('/'.join(','.join(map(str, group)) for group in nodes + [driver]))
print('; '.join(notes) or 'whole cores, one thread a node core', file=sys.stderr)
EOF
)" || { cat "$out/pinning.txt" >&2; exit 1; }
node1="${pinning%%/*}"
{
  echo "== pinning (node 1 / node 2 / node 3 / driver)"
  echo "$pinning"
  cat "$out/pinning.txt"
} >> "$out/machine.txt"
note "pinning: $pinning ($(cat "$out/pinning.txt"))"
if [ "$plan" = 1 ]; then
  grep -E 'Model name|^CPU\(s\)|Thread|Core|Socket|NUMA node\(s\)|^== cpu_' "$out/machine.txt" || true
  echo "node 1 / node 2 / node 3 / driver: $pinning"
  echo "($(cat "$out/pinning.txt"); described in $out/machine.txt)"
  exit 0
fi

# Everything it runs: on the allowed CPUs, under the cap.
confined() { scoped taskset -c "$allowed" "$@"; }

# A run cut short leaves its stores behind, those on tmpfs in memory.
shm=/dev/shm/vos-bench
mkdir -p "$shm"
cleanup() {
  # Nodes a killed bench left running hold their stores open: stop them
  # first.
  if [ "$scope" = 1 ]; then
    systemctl --user stop "vos-bench-$$-*.scope" 2> /dev/null || true
  else
    pkill -f -- "$(pwd)/target/release/vos node run" || true
  fi
  rm -rf -- "${shm:?}"/processes-*
  if [ -n "$disk" ]; then rm -rf -- "${disk:?}"/processes-*; fi
}
trap cleanup EXIT

# --- The builds -----------------------------------------------------------------
note "building (the first build installs the pinned toolchains and takes a while)"
{
  (cd agent/programs && confined nice -n 10 cargo build --release -p vos-agent --target ../../pvm/guest/riscv64em-vos.json)
  (cd agent/test-actors && confined nice -n 10 cargo build --release --target ../../pvm/guest/riscv64em-vos.json)
  confined nice -n 10 cargo bench -p vos-cli --bench processes --no-run
  confined nice -n 10 cargo bench -p vos-node --bench acceptance --no-run
} > "$out/build.log" 2>&1 || { note "the build failed: see $out/build.log"; exit 1; }

# --- The runs -------------------------------------------------------------------
# One run of the process bench: its name, then its settings.
rows() {
  local run="$1"
  shift
  note "running $run"
  if ! (
    export "$@" CPUS="$pinning"
    scoped taskset -c "$allowed" cargo bench -q -p vos-cli --bench processes
  ) > "$out/$run.log" 2>&1; then
    note "$run failed: see $out/$run.log"
  fi
}

note "running the in-process bench, on node 1's CPUs"
scoped taskset -c "$node1" cargo bench -q -p vos-node --bench acceptance \
  > "$out/in-process.log" 2>&1 || note "in-process failed: see $out/in-process.log"

rows tmpfs-agent DATA="$shm" ROWS=agent,quiet,query,linearizable,idle,failover-idle
rows tmpfs-agent-spread DATA="$shm" ROWS=agent SPREAD=1
rows tmpfs-agents DATA="$shm" ROWS=agents,failover
if [ -n "$disk" ]; then
  rows disk-agent DATA="$disk" ROWS=agent,quiet
  rows disk-agents DATA="$disk" ROWS=agents
fi
if [ "$soak" = 1 ]; then
  rows tmpfs-soak DATA="$shm" ROWS=soak SOAK_SECONDS=900 SOAK_WARMUP=100
fi

# --- The summary ----------------------------------------------------------------
{
  echo "== machine"
  grep -E 'Model name|^CPU\(s\)|Thread|Core|Socket|NUMA node\(s\)|^== cpu_' "$out/machine.txt" || true
  echo "pinning: $pinning ($(cat "$out/pinning.txt"))"
  for log in "$out"/*.log; do
    [ "$(basename "$log")" = build.log ] && continue
    echo "== $(basename "$log" .log)"
    grep -E "^(agent, |64 agents|quiet node|query|idle node|failover|soak|every agent|under load|  of which|  (the )?stages|  stalls|one request|pinned:)" "$log" || true
  done
} > "$out/summary.txt"
tar czf "$out.tar.gz" -C "$here" "$name"
note "done: $out/summary.txt, and $out.tar.gz to send back"
