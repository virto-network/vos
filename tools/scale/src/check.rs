//! `check`: what each host is, read there by one script, and whether a
//! run may use it. A host is refused for what would make a run's numbers
//! mislead or fail: another architecture, a kernel the JIT cannot use, a
//! clock off by more than the bound, a node on Wi-Fi, too little memory or disk,
//! missing tools, a port taken, or (over ssh) a user manager that ends
//! with the session. What only skews the numbers (a governor other than
//! `performance`, a rotating disk, a link under 1 GbE or of unknown speed,
//! a driver on Wi-Fi) is warned of, and recorded with the run. Each
//! driver's round trips to the nodes' machines are measured and recorded,
//! so a run's latencies can be read against its link.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::hosts::{self, quote};
use crate::inventory::{Harness, Host, Inventory, Role};

/// The probe: `key=value` lines of what the host is.
const PROBE: &str = r#"
set +e
mkdir -p "$DIR"
echo "arch=$(uname -m)"
echo "kernel=$(uname -r)"
echo "cpu=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
echo "cpus=$(getconf _NPROCESSORS_ONLN)"
echo "clk_tck=$(getconf CLK_TCK)"
echo "governors=$(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u | paste -sd, -)"
echo "mem_total_kb=$(awk '/^MemTotal/{print $2}' /proc/meminfo)"
echo "mem_available_kb=$(awk '/^MemAvailable/{print $2}' /proc/meminfo)"
echo "disk_free_kb=$(df -Pk "$DIR" | awk 'NR==2{print $4}')"
source=$(findmnt -no SOURCE -T "$DIR" | sed 's/\[.*//')
echo "disk_source=$source"
disk=$(lsblk -nsro NAME,TYPE "$source" 2>/dev/null | awk '$2=="disk"{print $1; exit}')
echo "disk=$disk"
if [ -n "$disk" ]; then
  echo "disk_rotational=$(cat /sys/block/$disk/queue/rotational 2>/dev/null)"
  echo "disk_transport=$(lsblk -ndo TRAN /dev/$disk 2>/dev/null | tr -d ' ')"
  echo "disk_model=$(cat /sys/block/$disk/device/model 2>/dev/null | sed 's/ *$//')"
fi
iface=$(ip -o addr show | awk -v a="$ADDR" '{split($4,p,"/"); if (p[1]==a) {print $2; exit}}')
echo "iface=$iface"
if [ -n "$iface" ]; then
  if [ -e "/sys/class/net/$iface/wireless" ] || [ -e "/sys/class/net/$iface/phy80211" ]; then echo "wireless=1"; else echo "wireless=0"; fi
  echo "link_mbps=$(cat /sys/class/net/$iface/speed 2>/dev/null || true)"
fi
for tool in rsync systemd-run systemctl taskset ss lsblk; do
  command -v "$tool" >/dev/null || echo "missing=$tool"
done
if systemctl --user show-environment >/dev/null 2>&1; then echo "user_manager=1"; else echo "user_manager=0"; fi
echo "linger=$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || echo unknown)"
if [ -n "$INGRESS" ] && [ -n "$(ss -Hltn "sport = :$INGRESS" 2>/dev/null)" ]; then echo "taken=tcp/$INGRESS"; fi
if [ -n "$PEER" ] && [ -n "$(ss -Hlun "sport = :$PEER" 2>/dev/null)" ]; then echo "taken=udp/$PEER"; fi
echo "machine_id=$(cat /etc/machine-id 2>/dev/null)"
echo "ntp_synchronized=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
if command -v chronyc >/dev/null; then
  echo "chrony_offset_s=$(chronyc tracking 2>/dev/null | awk '/^System time/{print ($6=="slow" ? "-" : "") $4}')"
fi
echo "freq_cur_khz=$(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq 2>/dev/null | awk '{s+=$1} END {if (NR) printf "%d", s/NR}')"
echo "freq_max_khz=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null)"
"#;

/// The kernel the PVM's JIT needs.
const MIN_KERNEL: (u32, u32) = (6, 7);
/// The least free space a node host's data disk must have.
const MIN_FREE_DISK_KB: u64 = 10 << 20;
/// What a machine keeps free beyond its units' memory caps: its kernel,
/// page cache and whatever else it runs.
const MEMORY_RESERVE_KB: u64 = 2 << 20;

/// A host's facts, as the probe read them, and the verdict on it.
#[derive(Clone, Debug, Default, Serialize, serde::Deserialize)]
pub struct Facts {
    pub name: String,
    pub role: String,
    pub address: String,
    pub weight: u32,
    pub cores: Option<String>,
    /// Everything the probe printed, by key; a repeated key's values
    /// joined by commas.
    pub probe: BTreeMap<String, String>,
    /// How far its clock runs ahead of the coordinator's, at the probe's
    /// midpoint, and the round trip it was read within.
    pub clock_offset_ms: f64,
    pub clock_rtt_ms: f64,
    /// A driver's round trips to each node machine's address.
    #[serde(default)]
    pub links: Vec<Link>,
    pub refused: Vec<String>,
    pub warnings: Vec<String>,
}

/// A driver's round trips to one address: pings sent a fifth of a second
/// apart, their quantiles and the share lost.
#[derive(Clone, Debug, Default, Serialize, serde::Deserialize)]
pub struct Link {
    pub to: String,
    pub sent: u32,
    pub lost: u32,
    pub p50_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

/// How many pings a link's measure sends.
const PINGS: u32 = 50;

/// The round trips from `host` to `address`, `pings` of them read by
/// `ping` there.
fn link(host: &Host, address: &str, pings: u32) -> Result<Link, String> {
    let text = hosts::run(
        host,
        &format!(
            "ping -n -c {pings} -i 0.2 -W 1 {} 2>&1; true",
            quote(address)
        ),
    )?;
    let mut times: Vec<f64> = text
        .lines()
        .filter_map(|line| {
            line.split_once("time=")?
                .1
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .collect();
    if times.is_empty() {
        return Err(format!("{}: no ping answered from {address}", host.name));
    }
    times.sort_by(f64::total_cmp);
    let at = |q: f64| times[((times.len() - 1) as f64 * q).round() as usize];
    Ok(Link {
        to: address.to_string(),
        sent: pings,
        lost: pings.saturating_sub(times.len() as u32),
        p50_ms: at(0.5),
        p99_ms: at(0.99),
        max_ms: times[times.len() - 1],
    })
}

/// Measure every reachable driver's links to the nodes' distinct
/// addresses, in parallel; a link that cannot be measured is warned of.
fn measure_links(facts: &mut [Facts], hosts: &[Host]) {
    let mut nodes: Vec<&str> = hosts
        .iter()
        .filter(|host| host.role == Role::Node)
        .map(|host| host.address.as_str())
        .collect();
    nodes.sort_unstable();
    nodes.dedup();
    std::thread::scope(|scope| {
        let measures: Vec<_> = facts
            .iter_mut()
            .zip(hosts)
            .filter(|(facts, host)| host.role == Role::Driver && facts.get("iface").is_some())
            .map(|(facts, host)| {
                let nodes = &nodes;
                scope.spawn(move || {
                    for address in nodes {
                        match link(host, address, PINGS) {
                            Ok(link) => facts.links.push(link),
                            Err(error) => facts.warnings.push(format!("its link: {error}")),
                        }
                    }
                })
            })
            .collect();
        for measure in measures {
            measure.join().expect("a link thread");
        }
    });
}

impl Facts {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.probe
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    pub fn number(&self, key: &str) -> Option<u64> {
        self.get(key)?.parse().ok()
    }

    /// The cores its process may use: those `cores` lists, else all.
    pub fn cores_used(&self) -> u64 {
        match &self.cores {
            Some(list) => list
                .split(',')
                .map(|part| match part.split_once('-') {
                    Some((low, high)) => {
                        let (low, high): (u64, u64) =
                            (low.parse().unwrap_or(0), high.parse().unwrap_or(0));
                        high.saturating_sub(low) + 1
                    }
                    None => 1,
                })
                .sum(),
            None => self.number("cpus").unwrap_or(1),
        }
    }
}

/// The host's clock against the coordinator's: of eight reads over one
/// session, the offset at the midpoint of the one with the shortest round
/// trip, and that round trip, the offset's bound being half of it.
fn clock(host: &Host) -> Result<(f64, f64), String> {
    let reads = hosts::clock_reads(host, 8)?;
    let (sent, rtt, theirs) = reads
        .into_iter()
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .ok_or_else(|| format!("{}: no clock read", host.name))?;
    Ok((theirs - (sent + rtt / 2.0), rtt))
}

/// Probe `host`: its facts, without a verdict.
pub fn probe(host: &Host) -> Result<Facts, String> {
    let (ingress, peer) = match host.role {
        Role::Node => (host.ingress.to_string(), host.peer.to_string()),
        Role::Driver => (String::new(), String::new()),
    };
    let script = format!(
        "DIR={} ADDR={} INGRESS={} PEER={}\n{PROBE}",
        quote(&host.dir),
        quote(&host.address),
        quote(&ingress),
        quote(&peer)
    );
    let text = hosts::run(host, &script)?;
    let mut probe: BTreeMap<String, String> = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            probe
                .entry(key.to_string())
                .and_modify(|kept| {
                    kept.push(',');
                    kept.push_str(value);
                })
                .or_insert_with(|| value.to_string());
        }
    }
    let (clock_offset_ms, clock_rtt_ms) = clock(host)?;
    Ok(Facts {
        name: host.name.clone(),
        role: format!("{:?}", host.role).to_lowercase(),
        address: host.address.clone(),
        weight: host.weight,
        cores: host.cores.clone(),
        probe,
        clock_offset_ms,
        clock_rtt_ms,
        links: Vec::new(),
        refused: Vec::new(),
        warnings: Vec::new(),
    })
}

fn kernel_at_least(release: &str, (major, minor): (u32, u32)) -> bool {
    let mut parts = release
        .split(|c: char| !c.is_ascii_digit())
        .map(|part| part.parse::<u32>().unwrap_or(0));
    let found = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    found >= (major, minor)
}

/// Bytes in a systemd size: `16G`, `512M`, or plain bytes.
fn size_kb(text: &str) -> Option<u64> {
    let (digits, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len()),
    );
    let value: u64 = digits.parse().ok()?;
    let shift = match unit {
        "" => return Some(value >> 10),
        "K" => 0,
        "M" => 10,
        "G" => 20,
        "T" => 30,
        _ => return None,
    };
    Some(value << shift)
}

/// The verdict on `facts`: what refuses the host, and what is only
/// warned of.
pub fn judge(facts: &mut Facts, host: &Host, harness: &Harness) {
    let mut refused = Vec::new();
    let mut warnings = Vec::new();
    match facts.get("arch") {
        Some("x86_64") => {}
        other => refused.push(format!("{other:?}: the runs use x86_64 hosts alone")),
    }
    let kernel = facts.get("kernel").unwrap_or("?").to_string();
    if !kernel_at_least(&kernel, MIN_KERNEL) {
        let text = format!("kernel {kernel}: the JIT needs Linux 6.7 or later");
        if host.old_kernel || host.role == Role::Driver {
            warnings.push(text);
        } else {
            refused.push(format!(
                "{text}: exclude it, or weight it down and set old_kernel"
            ));
        }
    }
    if facts.clock_offset_ms.abs() > harness.max_clock_offset_ms as f64 {
        refused.push(format!(
            "its clock is {:.1} ms off the coordinator's, above {} ms",
            facts.clock_offset_ms, harness.max_clock_offset_ms
        ));
    }
    match (facts.get("iface"), facts.get("wireless")) {
        (None, _) => refused.push(format!("no interface holds {}", host.address)),
        (Some(_), Some("1")) if host.role == Role::Driver => warnings.push(
            "its link is Wi-Fi: its calls' latencies include the radio's, read them against its round trips".into(),
        ),
        (Some(_), Some("1")) => refused.push("its link is Wi-Fi".into()),
        (Some("lo"), _) => {}
        (Some(iface), _) => match facts.number("link_mbps").filter(|speed| *speed < 1 << 31) {
            None => warnings.push(format!("{iface}'s link speed is unknown")),
            Some(speed) if speed < 1000 => {
                warnings.push(format!("{iface} links at {speed} Mb/s, under 1 GbE"))
            }
            Some(_) => {}
        },
    }
    match facts.get("ntp_synchronized") {
        Some("yes") => {}
        Some("no") => warnings.push("its clock is not NTP-synchronised".into()),
        _ => warnings.push("whether its clock is NTP-synchronised is unknown".into()),
    }
    let governors = facts.get("governors").unwrap_or("unknown").to_string();
    if governors != "performance" {
        warnings.push(format!(
            "CPU governor {governors}: `performance` keeps the clock steady"
        ));
    }
    if let Some(missing) = facts.get("missing") {
        refused.push(format!("missing tools: {missing}"));
    }
    if facts.get("user_manager") != Some("1") {
        refused.push("no systemd user manager reachable".into());
    }
    if !host.is_local() && facts.get("linger") != Some("yes") {
        refused.push(format!(
            "its user's units end with the ssh session: `loginctl enable-linger {}`",
            host.ssh.split('@').next().unwrap_or("USER")
        ));
    }
    if let Some(taken) = facts.get("taken") {
        refused.push(format!("ports in use: {taken}"));
    }
    if host.role == Role::Node {
        match (facts.get("disk_rotational"), facts.get("disk_transport")) {
            (Some("1"), _) => warnings.push(
                "a rotating data disk: a group commits at its median replica's fsync, so it gates every group it follows".into(),
            ),
            (_, Some("usb")) => warnings.push("a USB data disk: its fsyncs may gate every group it follows".into()),
            (Some("0"), _) => {}
            _ => warnings.push("its data disk's type is unknown".into()),
        }
        let available = facts.number("mem_available_kb").unwrap_or(0);
        if available < 2 << 20 {
            refused.push(format!("{} MiB of memory free", available >> 10));
        }
        let free = facts.number("disk_free_kb").unwrap_or(0);
        if free < MIN_FREE_DISK_KB {
            refused.push(format!("{} MiB free on its data disk", free >> 10));
        }
    }
    facts.refused = refused;
    facts.warnings = warnings;
}

/// The verdicts on the hosts together, by machine (its machine id, else
/// its ssh host): the memory caps of a machine's entries must fit in what
/// it has free less a reserve, the nodes sharing one data disk need its
/// free space each, and a node's machine holds no driver and is not the
/// coordinator's, unless the inventory is a smoke's. Several nodes may
/// share a machine, each with its own dir and ports; drivers and the
/// coordinator may share one that holds no node.
pub fn judge_machines(facts: &mut [Facts], hosts: &[Host], harness: &Harness, coordinator: &str) {
    let machine = |facts: &Facts, host: &Host| {
        facts
            .get("machine_id")
            .map(str::to_string)
            .unwrap_or_else(|| host.machine().to_string())
    };
    let machines: Vec<String> = facts
        .iter()
        .zip(hosts)
        .map(|(facts, host)| machine(facts, host))
        .collect();
    for at in 0..facts.len() {
        let mine: Vec<usize> = (0..facts.len())
            .filter(|other| machines[*other] == machines[at])
            .collect();
        let caps: u64 = mine
            .iter()
            .map(|other| size_kb(hosts[*other].memory_max(harness)).unwrap_or(0))
            .sum();
        let available = facts[at].number("mem_available_kb").unwrap_or(0);
        let names: Vec<&str> = mine
            .iter()
            .map(|other| hosts[*other].name.as_str())
            .collect();
        if caps + MEMORY_RESERVE_KB > available {
            facts[at].refused.push(format!(
                "the memory caps of {} on its machine ({} MiB) and a {} MiB reserve exceed its {} MiB free",
                names.join(", "),
                caps >> 10,
                MEMORY_RESERVE_KB >> 10,
                available >> 10
            ));
        }
        if hosts[at].role == Role::Node {
            let disk = facts[at].get("disk_source").map(str::to_string);
            let sharing = mine
                .iter()
                .filter(|other| {
                    hosts[**other].role == Role::Node
                        && facts[**other].get("disk_source").map(str::to_string) == disk
                })
                .count() as u64;
            let free = facts[at].number("disk_free_kb").unwrap_or(0);
            if sharing > 1 && free < sharing * MIN_FREE_DISK_KB {
                facts[at].refused.push(format!(
                    "{sharing} nodes share its data disk, {} MiB free: {} MiB each at least",
                    free >> 10,
                    MIN_FREE_DISK_KB >> 10
                ));
            }
        }
        let node = mine.iter().any(|other| hosts[*other].role == Role::Node);
        let driver = mine.iter().any(|other| hosts[*other].role == Role::Driver);
        let coordinating = hosts[at].is_local() || machines[at] == coordinator;
        let shared = match (node, driver, coordinating) {
            (true, true, true) => Some("a node, a driver and the coordinator share its machine"),
            (true, true, false) => Some("a node and a driver share its machine"),
            (true, false, true) => Some("a node and the coordinator share its machine"),
            _ => None,
        };
        if let Some(shared) = shared {
            if harness.smoke {
                facts[at]
                    .warnings
                    .push(format!("{shared}: a smoke's numbers only"));
            } else {
                facts[at].refused.push(format!(
                    "{shared}: drivers and the coordinator take a node's CPU and link during a timed run"
                ));
            }
        }
    }
}

/// Probe and judge every host of `inventory`, in parallel: the facts in
/// inventory order. A host that cannot be reached is refused.
pub fn check(inventory: &Inventory) -> Vec<Facts> {
    let coordinator = std::fs::read_to_string("/etc/machine-id")
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut facts = probe_all(inventory);
    measure_links(&mut facts, &inventory.hosts);
    judge_machines(
        &mut facts,
        &inventory.hosts,
        &inventory.harness,
        &coordinator,
    );
    facts
}

fn probe_all(inventory: &Inventory) -> Vec<Facts> {
    std::thread::scope(|scope| {
        let probes: Vec<_> = inventory
            .hosts
            .iter()
            .map(|host| scope.spawn(move || (host, probe(host))))
            .collect();
        probes
            .into_iter()
            .map(|probe| {
                let (host, probed) = probe.join().expect("a probe thread");
                match probed {
                    Ok(mut facts) => {
                        judge(&mut facts, host, &inventory.harness);
                        facts
                    }
                    Err(error) => Facts {
                        name: host.name.clone(),
                        role: format!("{:?}", host.role).to_lowercase(),
                        address: host.address.clone(),
                        refused: vec![format!("unreachable: {error}")],
                        ..Facts::default()
                    },
                }
            })
            .collect()
    })
}

/// The facts as a table: a row a host, then its refusals and warnings.
pub fn table(facts: &[Facts]) -> String {
    let mut text = format!(
        "{:<14} {:<6} {:<10} {:>5} {:>8} {:>9} {:<14} {:<14} {:>7} {:>8}  {}\n",
        "host",
        "role",
        "kernel",
        "cpus",
        "mem GiB",
        "disk GiB",
        "disk",
        "governor",
        "link",
        "clock ms",
        "verdict"
    );
    for host in facts {
        let disk = match (host.get("disk"), host.get("disk_rotational")) {
            (Some(disk), Some("1")) => format!("{disk} (hdd)"),
            (Some(disk), Some("0")) => format!(
                "{disk} ({})",
                host.get("disk_transport").unwrap_or("ssd, bus ?")
            ),
            (Some(disk), _) => format!("{disk} (?)"),
            (None, _) => "?".into(),
        };
        let link = match (host.get("iface"), host.get("link_mbps")) {
            (Some("lo"), _) => "lo".to_string(),
            (Some(_), _) if host.get("wireless") == Some("1") => "wifi".into(),
            (Some(_), Some(speed)) => format!("{speed}M"),
            (Some(iface), None) => format!("{iface}?"),
            (None, _) => "?".into(),
        };
        let verdict = if !host.refused.is_empty() {
            "REFUSED"
        } else if !host.warnings.is_empty() {
            "ok, warned"
        } else {
            "ok"
        };
        text += &format!(
            "{:<14} {:<6} {:<10} {:>5} {:>8.1} {:>9.1} {:<14} {:<14} {:>7} {:>8.1}  {verdict}\n",
            host.name,
            host.role,
            host.get("kernel")
                .unwrap_or("?")
                .split('-')
                .next()
                .unwrap_or("?"),
            host.get("cpus").unwrap_or("?"),
            host.number("mem_available_kb").unwrap_or(0) as f64 / (1 << 20) as f64,
            host.number("disk_free_kb").unwrap_or(0) as f64 / (1 << 20) as f64,
            disk,
            host.get("governors").unwrap_or("?"),
            link,
            host.clock_offset_ms,
        );
    }
    for host in facts {
        for link in &host.links {
            text += &format!(
                "{}: link to {}: p50 {:.1} ms, p99 {:.1} ms, max {:.1} ms, {} of {} lost\n",
                host.name, link.to, link.p50_ms, link.p99_ms, link.max_ms, link.lost, link.sent
            );
        }
    }
    for host in facts {
        for refusal in &host.refused {
            text += &format!("{}: refused: {refusal}\n", host.name);
        }
        for warning in &host.warnings {
            text += &format!("{}: warning: {warning}\n", host.name);
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::{Facts, judge, judge_machines, kernel_at_least, size_kb};
    use crate::inventory::Inventory;

    fn inventory() -> Inventory {
        Inventory::parse(
            r#"
            [[host]]
            name = "a"
            ssh = "me@10.0.0.1"
            address = "10.0.0.1"
            role = "node"
            dir = "/data/a"
            ingress = 7001
            peer = 7101
            [[host]]
            name = "b"
            ssh = "localhost"
            address = "127.0.0.1"
            role = "node"
            dir = "/srv/b"
            ingress = 7002
            peer = 7102
            [[host]]
            name = "c"
            ssh = "localhost"
            address = "127.0.0.1"
            role = "node"
            dir = "/srv/c"
            ingress = 7003
            peer = 7103
            "#,
        )
        .unwrap()
    }

    fn good() -> Facts {
        let mut facts = Facts::default();
        for (key, value) in [
            ("arch", "x86_64"),
            ("kernel", "6.12.9-arch1"),
            ("cpus", "16"),
            ("governors", "performance"),
            ("mem_available_kb", "33554432"),
            ("disk_free_kb", "104857600"),
            ("disk", "nvme0n1"),
            ("disk_rotational", "0"),
            ("iface", "enp3s0"),
            ("wireless", "0"),
            ("link_mbps", "2500"),
            ("user_manager", "1"),
            ("linger", "yes"),
            ("ntp_synchronized", "yes"),
        ] {
            facts.probe.insert(key.into(), value.into());
        }
        facts
    }

    fn judged(change: impl FnOnce(&mut Facts)) -> Facts {
        let inventory = inventory();
        let mut facts = good();
        change(&mut facts);
        judge(&mut facts, &inventory.hosts[0], &inventory.harness);
        facts
    }

    #[test]
    fn a_wired_host_with_a_steady_clock_passes() {
        let facts = judged(|_| {});
        assert!(facts.refused.is_empty(), "{:?}", facts.refused);
        assert!(facts.warnings.is_empty(), "{:?}", facts.warnings);
    }

    #[test]
    fn wifi_an_old_kernel_a_skewed_clock_or_another_arch_is_refused() {
        let refused = |change: fn(&mut Facts), word: &str| {
            let facts = judged(change);
            assert!(
                facts.refused.iter().any(|refusal| refusal.contains(word)),
                "{word}: {:?}",
                facts.refused
            );
        };
        refused(
            |facts| {
                facts.probe.insert("wireless".into(), "1".into());
            },
            "Wi-Fi",
        );
        refused(
            |facts| {
                facts.probe.insert("kernel".into(), "6.6.30".into());
            },
            "6.7",
        );
        refused(|facts| facts.clock_offset_ms = -150.0, "100 ms");
        refused(
            |facts| {
                facts.probe.insert("arch".into(), "aarch64".into());
            },
            "x86_64",
        );
        refused(
            |facts| {
                facts.probe.insert("linger".into(), "no".into());
            },
            "enable-linger",
        );
        refused(
            |facts| {
                facts.probe.insert("missing".into(), "rsync".into());
            },
            "rsync",
        );
        refused(
            |facts| {
                facts.probe.insert("taken".into(), "tcp/7001".into());
            },
            "tcp/7001",
        );
    }

    #[test]
    fn a_slow_link_a_rotating_disk_or_a_saving_governor_is_warned_of() {
        let facts = judged(|facts| {
            facts.probe.insert("link_mbps".into(), "100".into());
            facts.probe.insert("disk_rotational".into(), "1".into());
            facts.probe.insert("governors".into(), "powersave".into());
        });
        assert!(facts.refused.is_empty(), "{:?}", facts.refused);
        assert_eq!(facts.warnings.len(), 3, "{:?}", facts.warnings);
    }

    #[test]
    fn a_usb_or_unknown_disk_or_an_unsynchronised_clock_is_warned_of() {
        for (change, word) in [
            (("disk_transport", "usb"), "USB"),
            (("disk_rotational", ""), "unknown"),
            (("ntp_synchronized", "no"), "NTP"),
        ] {
            let facts = judged(|facts| {
                facts.probe.insert(change.0.into(), change.1.into());
            });
            assert!(facts.refused.is_empty(), "{:?}", facts.refused);
            assert!(
                facts.warnings.iter().any(|warning| warning.contains(word)),
                "{word}: {:?}",
                facts.warnings
            );
        }
    }

    #[test]
    fn a_machine_whose_caps_do_not_fit_or_that_mixes_roles_is_refused() {
        let text = r#"
            [harness]
            memory_max = "8G"
            [[host]]
            name = "a"
            ssh = "me@10.0.0.1"
            address = "10.0.0.1"
            role = "node"
            dir = "/data/a"
            ingress = 7001
            peer = 7101
            [[host]]
            name = "b"
            ssh = "me@10.0.0.1"
            address = "10.0.0.1"
            role = "node"
            dir = "/data/b"
            ingress = 7002
            peer = 7102
            [[host]]
            name = "c"
            ssh = "me@10.0.0.3"
            address = "10.0.0.3"
            role = "node"
            dir = "/data/c"
            ingress = 7001
            peer = 7101
            [[host]]
            name = "d"
            ssh = "me@10.0.0.3"
            address = "10.0.0.3"
            role = "driver"
            dir = "/data/d"
        "#;
        let mut inventory = Inventory::parse(text).unwrap();
        let machines = ["m1", "m1", "m3", "m3"];
        let judged = |inventory: &Inventory, free_gib: u64, coordinator: &str| {
            let mut facts: Vec<Facts> = machines
                .iter()
                .map(|machine| {
                    let mut facts = good();
                    facts.probe.insert("machine_id".into(), machine.to_string());
                    facts
                        .probe
                        .insert("mem_available_kb".into(), (free_gib << 20).to_string());
                    facts
                })
                .collect();
            judge_machines(
                &mut facts,
                &inventory.hosts,
                &inventory.harness,
                coordinator,
            );
            facts
        };
        // Two 8 GiB caps and the reserve need 18 GiB on m1.
        let facts = judged(&inventory, 17, "none");
        assert!(
            facts[0]
                .refused
                .iter()
                .any(|refusal| refusal.contains("memory caps")),
            "{:?}",
            facts[0].refused
        );
        assert!(judged(&inventory, 64, "none")[0].refused.is_empty());
        // A driver beside a node, and the coordinator on a node's machine.
        let facts = judged(&inventory, 64, "m1");
        assert!(
            facts[2]
                .refused
                .iter()
                .any(|refusal| refusal.contains("a node and a driver"))
        );
        assert!(
            facts[0]
                .refused
                .iter()
                .any(|refusal| refusal.contains("the coordinator"))
        );
        inventory.harness.smoke = true;
        let facts = judged(&inventory, 64, "m1");
        assert!(facts.iter().all(|facts| facts.refused.is_empty()));
        assert!(
            facts[2]
                .warnings
                .iter()
                .any(|warning| warning.contains("smoke"))
        );
    }

    /// Three nodes on one machine (each its dir and ports, their caps
    /// summed), the drivers and the coordinator on another that holds no
    /// node: the two machines a scale run has.
    #[test]
    fn three_nodes_on_one_machine_and_the_drivers_on_the_coordinator_pass() {
        let mut text = String::from("[harness]\nmemory_max = \"8G\"\n");
        for at in 1..=3 {
            text += &format!(
                "[[host]]\nname = \"c{at}\"\nssh = \"owner@10.0.0.2\"\naddress = \"10.0.0.2\"\nrole = \"node\"\ndir = \"/srv/vos-scale/n{at}\"\ncores = \"{}-{}\"\ningress = {}\npeer = {}\n",
                4 * (at - 1),
                4 * at - 1,
                7700 + at,
                7800 + at
            );
        }
        for at in 1..=2 {
            text += &format!(
                "[[host]]\nname = \"d{at}\"\nssh = \"localhost\"\naddress = \"10.0.0.1\"\nrole = \"driver\"\ndir = \"/var/tmp/vos-scale/d{at}\"\nmemory_max = \"2G\"\n"
            );
        }
        let inventory = Inventory::parse(&text).unwrap();
        let judged = |free_gib: u64, disk_free_gib: u64| {
            let mut facts: Vec<Facts> = inventory
                .hosts
                .iter()
                .map(|host| {
                    let mut facts = good();
                    let machine = if host.is_local() { "desk" } else { "compumax" };
                    facts.probe.insert("machine_id".into(), machine.into());
                    facts
                        .probe
                        .insert("mem_available_kb".into(), (free_gib << 20).to_string());
                    facts
                        .probe
                        .insert("disk_source".into(), "/dev/nvme0n1p2".into());
                    facts
                        .probe
                        .insert("disk_free_kb".into(), (disk_free_gib << 20).to_string());
                    judge(&mut facts, host, &inventory.harness);
                    facts
                })
                .collect();
            judge_machines(&mut facts, &inventory.hosts, &inventory.harness, "desk");
            facts
        };
        let facts = judged(32, 100);
        assert!(
            facts.iter().all(|facts| facts.refused.is_empty()),
            "{:?}",
            facts.iter().map(|facts| &facts.refused).collect::<Vec<_>>()
        );
        assert!(facts.iter().all(|facts| facts.warnings.is_empty()));
        // Three 8 GiB caps and the reserve need 26 GiB on compumax.
        let facts = judged(25, 100);
        assert!(
            facts[0]
                .refused
                .iter()
                .any(|refusal| refusal.contains("memory caps"))
        );
        assert!(
            facts[3].refused.is_empty(),
            "the drivers' machine: {:?}",
            facts[3].refused
        );
        // Three nodes on one disk need its free space thrice.
        let facts = judged(32, 25);
        assert!(
            facts[0]
                .refused
                .iter()
                .any(|refusal| refusal.contains("share its data disk"))
        );
        assert!(facts[3].refused.is_empty());
    }

    #[test]
    fn a_driver_on_wifi_is_warned_of_and_a_node_on_wifi_refused() {
        let mut text = String::new();
        for at in 1..=3 {
            text += &format!(
                "[[host]]\nname = \"n{at}\"\nssh = \"me@10.0.0.2\"\naddress = \"10.0.0.2\"\nrole = \"node\"\ndir = \"/srv/n{at}\"\ningress = {}\npeer = {}\n",
                7000 + at,
                7100 + at
            );
        }
        text += r#"
            [[host]]
            name = "d"
            ssh = "localhost"
            address = "10.0.0.1"
            role = "driver"
            dir = "/var/tmp/d"
            "#;
        let inventory = Inventory::parse(&text).unwrap();
        let judged = |at: usize| {
            let mut facts = good();
            facts.probe.insert("wireless".into(), "1".into());
            judge(&mut facts, &inventory.hosts[at], &inventory.harness);
            facts
        };
        let node = judged(0);
        assert!(node.refused.iter().any(|refusal| refusal.contains("Wi-Fi")));
        let driver = judged(3);
        assert!(driver.refused.is_empty(), "{:?}", driver.refused);
        assert!(
            driver
                .warnings
                .iter()
                .any(|warning| warning.contains("Wi-Fi"))
        );
    }

    #[test]
    fn a_link_is_measured_by_its_round_trips() {
        let inventory = inventory();
        let link = super::link(&inventory.hosts[1], "127.0.0.1", 3).unwrap();
        assert_eq!((link.sent, link.lost), (3, 0));
        assert!(link.p50_ms <= link.p99_ms && link.p99_ms <= link.max_ms);
        assert!(link.max_ms < 50.0, "{link:?}");
    }

    #[test]
    fn this_machines_clock_reads_over_one_session() {
        let inventory = inventory();
        let (offset, rtt) = super::clock(&inventory.hosts[1]).unwrap();
        assert!(offset.abs() < 50.0 && rtt < 50.0, "{offset} {rtt}");
    }

    #[test]
    fn kernels_and_sizes_read() {
        assert!(kernel_at_least("6.7.0", (6, 7)));
        assert!(kernel_at_least("7.1.13-2-MANJARO", (6, 7)));
        assert!(!kernel_at_least("6.6.87-1-lts", (6, 7)));
        assert!(!kernel_at_least("5.15.0", (6, 7)));
        assert_eq!(size_kb("16G"), Some(16 << 20));
        assert_eq!(size_kb("512M"), Some(512 << 10));
        assert_eq!(size_kb("lots"), None);
    }
}
