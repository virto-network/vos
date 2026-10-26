# vos-scale: the scale test's harness

`vos-scale` runs the scale test (`docs/design/slice-7-mobile.md`, "The
scale test") on the owner's LAN machines. It runs on one machine, the
coordinator, and reaches every other host over ssh. An `inventory.toml`
drives it, with one `[[host]]` entry for each node or driver.

| command | what it does |
|---|---|
| `check` | Reads every host: architecture, kernel, clock offset, free memory and disk, the data disk's type, CPU and governor, the link's speed, the tools, the user manager, and whether the ports are free. It refuses a host that would make the numbers mislead, and exits 1 if it refuses any host. |
| `deploy` | Ships the static `vos` and `vos-scale` and the agent's ELF to every host with `rsync`, wipes the nodes' data, makes each node's key, and founds a new space. |
| `up` | Starts a run: each node and each host's sampler in a `systemd-run --user` unit under a memory cap. Ingress uses each node's own TLS, pinned by its key, so the harness makes no certificates. |
| `agents` | Creates the `K` ledger shards and `I` idle agents on three nodes each, picked by weight, with the shard actor installed in each; `--identity-rows U` creates the stand-in identity agent on every node and writes its rows; `--representative` creates the space's representative first. |
| `drive` | Drives the load model from every driver host while it polls each node's `/stats` and `/agents/*/status`. |
| `collect` | Copies each host's samples, node log and driver record into the run's directory. |
| `down` | Stops every unit on every host, by unit name. |
| `report` | Summarises a run: each host's binding resource, the nodes' stages, leader changes, the drivers' rates and latencies, and the slowest node host. `--compare RUN` sets two runs side by side. |
| `run` | Does all of these with one command: deploy, up, agents, drive, collect, down, report. |

`--exclude NAME`, given before the command, leaves a host out as if the
inventory did not list it. Use it for a second run without the slowest host.
That needs four node hosts or more: every agent has three replicas, so a
space needs three nodes after one is left out. `down` and `deploy` still
stop the harness's units on an excluded host. `run` stops every unit when it
fails partway or is interrupted (Ctrl-C). Every unit also has a runtime cap
(`harness.max_run_s`, and a driver's load plus five minutes).
Each run gets its own directory under `runs/` (set by `harness.runs`). The
directory holds the inventory, the hosts' facts (`hosts.json`), the versions
and space (`deployed.json`), the agents, the polls (`nodes.jsonl`), each
host's samples and logs (`hosts/<name>/`), `summary.json` and `report.txt`.

## The load model

`drive` offers one load, set by one rate: `U` users (`--users`), a share
`a` of them active at once (`--active`, 5%), each making `r` calls a
second while active (`--per-user`, 0.1; or `--rate` for `U·a·r` itself).

- **Users** are keys derived from the seed and their index; nothing is
  stored. Each has an account in one of the `K` ledger shards, by hash.
- **Who is active** is drawn Zipf(1.0) over the users (`--zipf`): a user
  becomes active, stays so for an exponential span (`--active-s`, mean
  300 s) making `r` calls a second, and is replaced. Its session opens at
  its first call and is kept.
- **Calls** arrive open loop, as a Poisson process, and each one's latency
  is timed from its scheduled send.
- **The mix** (`--mix`, `transfer=0.8,query=0.15,workflow=0.045,cut=0.005`
  by default, the harness's own shares pending the owner's): transfers, a share `x` of them to a payee in another shard
  (`--cross`; random payees' `1 − 1/K` by default), sent to the shard's
  leader; queries on a follower; workflows, read until they end; and reads
  at a cut, read again once their window closes (`B_w + D`) and timed from
  then (`cut_read`).
- **The identity agent** (`run --identity`, or `agents --identity-rows`)
  holds a row a user, replicated on every node; the first driver writes
  it `--identity-hz` times a second (10).
- **The readers** (`--readers`, 0 by default; T4's is 1%): a share of all
  the agents, the shards and the idle ones, each read once at a cut every
  window, at a uniform time within it (`reader`, and `reader_read` timed
  from the close).
- **The drivers** split the users and the rate. Each signs its calls ahead
  of their schedule, keeps at most `[harness] driver_connections` (512)
  connections a node, and sends each call once (no retry, no redirect
  followed). All the drivers' connections together must fit in the nodes'
  `[node] ingress_connections` (1,024 by default), or `drive` refuses. A
  call goes to its agent's leader as last learned, a query to a follower;
  a node that does not answer, or answers `Unavailable` or names no
  leader, is left out for 2 s and the leader's place moves to the next
  replica. Each operation is timed from its schedule (or from its send,
  if that came first: never from a later instant). A user's calls go one
  at a time, in order: a call scheduled while the user's last is
  unanswered waits for it (`queued`). A read at a cut is read again from
  its window's close, after a jitter of up to 0.5 s, every 0.5 s.
- **The record**, every interval: a line a kind (sent, answered, refusals
  by name, rate, p50, p99, p99.9, sends late, signatures the sending thread
  made), and a line for the mix with the driver's CPU in the interval, the
  requests that waited for a connection and the most in use. The totals
  add the load's span (its first and last sends, the report's window), the
  mix as sent against its target, the CPU over the load, and each shard's
  distinct users and sessions opened. The report warns when the
  connections bound or the driver fell behind. A machine may run several
  drivers, each its own entry, directory and cores.
- **The capacity probe:** a plan with `"probe": true`, given to
  `vos-scale drive-local --plan` by hand, sends every request to a node
  that does not replicate its agent, which answers `Elsewhere` at once.
  The driver does all its own work and the nodes almost none: its cost at
  a rate the nodes could not commit. It refuses to run when an agent is on
  every node, and writes no identity rows. Its total line's `load_cores`
  and `threads_cpu_s` give the CPU it took.
- **Not modeled**, as every report says: the per-call identity read,
  credentialed calls, cross-space traffic and proving.

## On each machine

Every host, nodes and drivers alike, needs:

- **x86-64 Linux 6.7 or later.** The PVM's JIT needs 6.7. A host on an
  older kernel can stay only with `old_kernel = true` and a lower
  `weight`. aarch64 hosts are not deployed to.
- **A wired link.** `check` refuses a node on Wi-Fi and warns of a driver
  on it. A link under 1 GbE, or of unknown speed, gets a warning: at the
  knee the NIC may be what binds. `check` also measures each driver's
  round trips to the nodes' machines (50 pings, `iputils`' `ping` on the
  driver) and records their p50, p99, maximum and losses in `hosts.json`,
  so a run's latencies can be read against its link.
- **Packages:** `rsync`, `openssh-server`, `systemd` (with a user manager),
  `util-linux` (`taskset`, `lsblk`, `findmnt`) and `iproute2` (`ip`, `ss`). Nothing
  else: `deploy` ships static binaries.
- **ssh by key** from the coordinator, as the user that runs the units.
  The harness uses batch mode, so log in once from the coordinator first
  (`ssh user@host true`) to accept the host key.
- **Lingering** for that user, so units outlive the ssh session:
  `sudo loginctl enable-linger USER`.
- **A synchronised clock** (chrony or systemd-timesyncd). `check`
  measures the offset over one ssh session, keeps the read with the
  shortest round trip, and refuses an offset above 100 ms. It warns when
  the host does not report NTP sync.
- **A directory of the harness's own on the data disk** for `dir`, with
  at least 10 GiB free. It must be absent or empty at the first deploy.
  The deploy marks it with a `.vos-scale` file, and later deploys wipe the
  node's data inside it. A deploy refuses a dir that holds other files, and
  it refuses `/` and `$HOME`.
  Prefer an SSD or NVMe: a group commits at its median replica's fsync, so
  a slow disk holds back every group the host follows.
- **The `performance` CPU governor** for timed runs
  (`sudo cpupower frequency-set -g performance`). Laptops run on AC
  power with their lid open. `check` warns about any other governor.
- **Open ports** between the hosts: each node's `ingress` (TCP) and
  `peer` (UDP).

The coordinator also needs the repository, built from its root:

    just release build-agent build-representative build-test-actors

`just release` builds the static `vos` and `vos-scale` under
`target/x86_64-unknown-linux-musl/release/`. `deploy` takes them from
there unless `--bins` says otherwise.

## Hardware-key ssh

Every remote command goes over one shared ssh connection a host
(`ControlMaster`, kept for 8 hours): a key that asks for a touch, such as
a YubiKey, asks once a host when the first command connects, not on every
command. Open the connections before a run, touching once each, with
`ssh -o ControlMaster=auto -o ControlPath=~/.ssh/vos-scale-%C -o ControlPersist=8h HOST true`;
close them after with `ssh -o ControlPath=~/.ssh/vos-scale-%C -O exit HOST`.

## The inventory

Copy `inventory.example.toml` to `inventory.toml` and give one
`[[host]]` entry for each node and each driver:

- `name`: unique, made of letters, digits, `-`, `_` and `.`. The
  host's units and run files are named after it.
- `ssh`: `user@address`, or `localhost` to run on the coordinator
  without ssh.
- `address`: the host's address on the wired LAN. Peers and clients
  reach it there, and `check` finds the interface that holds it.
- `role`: `node` or `driver`. A run needs three node hosts or more, and a
  run without the slowest needs four. `check` refuses a node's machine
  that also holds a driver or the coordinator, unless `harness.smoke` is
  set, as it is on one machine.
- `weight`: the host's share of agents' replicas against the other
  nodes'. A slower host gets a lower weight.
- `dir`: an absolute path on the data disk.
- `cores`: optional, as `taskset -c` takes them, e.g. `0-11`. Use it
  when the desktop runs two nodes, giving each its own cores, ports and
  `dir`.
- `ingress` and `peer`: the node's TCP and UDP ports.
- `memory_max`: optional; it overrides `harness.memory_max` for this host.
  On each machine, the caps of all its entries plus a 2 GiB reserve must
  fit in its free memory, or `check` refuses it.

`[harness]` sets where runs are kept, the units' memory cap, the window
length, the clock bound and the sampling interval. `[node]` holds the
nodes' settings (`vos node run --config`): `executors`, `queue`,
`max_inputs`, `max_bytes`, `linger_ms`, `ingress_connections`,
`election_timeout_ms = [low, high]` and `heartbeat_ms`.

## Running `check`

From the repository's root:

    target/x86_64-unknown-linux-musl/release/vos-scale -i inventory.toml check --json check.json

`check` prints a row for each host, then each refusal and warning. Fix
every refusal, or leave that host out with `--exclude NAME`. Warnings,
such as the governor, a rotating disk or a slow link, are recorded with
every run, and they name what may bind. Once every host passes, the
step's gate is one command (raise `ingress_connections` in `[node]`
when many users call at once):

    target/x86_64-unknown-linux-musl/release/vos-scale -i inventory.toml run \
        --shards 100 --identity --users 10000 --rate 200 --secs 300 --label gate

The report names the slowest node host: the one whose node has the highest
commit p99, with disk time per I/O breaking ties. With four node hosts or
more, rerun without it and compare the two runs:

    vos-scale -i inventory.toml --exclude SLOWEST run --shards 100 --users 10000 --rate 200 --secs 300 --label without-SLOWEST
    vos-scale -i inventory.toml report --compare <the first run's id>

`tools/scale/inventory.localhost.toml` runs the same thing on one machine.
It lists four nodes and a driver as `localhost` entries, and is marked
`smoke = true`.

The runs' layout (`inventory.example.toml`, decided S35): three nodes on
one machine, each its own entry with its own ports, cores and `dir`, and
the driver and the coordinator on the desktop. `check` sums a machine's
caps against its memory and its nodes' disk needs against the disk they
share, and refuses a node's machine only when a driver or the coordinator
is on it. With every node on one host, the rerun without the slowest
host cannot be made.

The report's window is the drivers' span, minus a ramp at the start (one
sampling interval by default; `--ramp-s` sets it, `--from-ms` and
`--to-ms` give the window outright). The report warns when a driver fell
behind its schedule, because then the driver may be what bound, not the
nodes.
