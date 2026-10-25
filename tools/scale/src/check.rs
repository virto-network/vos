//! `check`: what each host is, read there by one script, and whether a
//! run may use it. A host is refused for what would make a run's numbers
//! mislead or fail: another architecture, a kernel the JIT cannot use, a
//! clock off by more than the bound, Wi-Fi, too little memory or disk,
//! missing tools, a port taken, or (over ssh) a user manager that ends
//! with the session. What only skews the numbers (a governor other than
//! `performance`, a rotating disk, a link under 1 GbE or of unknown speed)
//! is warned of, and recorded with the run.

use std::collections::BTreeMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
echo "cpus=$(nproc --all)"
echo "clk_tck=$(getconf CLK_TCK)"
echo "governors=$(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u | paste -sd, -)"
echo "mem_total_kb=$(awk '/^MemTotal/{print $2}' /proc/meminfo)"
echo "mem_available_kb=$(awk '/^MemAvailable/{print $2}' /proc/meminfo)"
echo "disk_free_kb=$(df -Pk "$DIR" | awk 'NR==2{print $4}')"
source=$(df -P "$DIR" | awk 'NR==2{print $1}')
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
"#;

/// The kernel the PVM's JIT needs.
const MIN_KERNEL: (u32, u32) = (6, 7);
/// The least free space a node host's data disk must have.
const MIN_FREE_DISK_KB: u64 = 10 << 20;

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
    pub refused: Vec<String>,
    pub warnings: Vec<String>,
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

fn now_ms() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs_f64()
        * 1e3
}

/// The host's clock against the coordinator's: the offset at the
/// midpoint of the read with the shortest round trip of five.
fn clock(host: &Host) -> Result<(f64, f64), String> {
    let mut best: Option<(f64, f64)> = None;
    for _ in 0..5 {
        let sent = now_ms();
        let start = Instant::now();
        let text = hosts::run(host, "date +%s%N\n")?;
        let rtt = start.elapsed().as_secs_f64() * 1e3;
        let theirs: f64 =
            text.trim()
                .parse::<u128>()
                .map_err(|_| format!("{}: a clock of {text:?}", host.name))? as f64
                / 1e6;
        let offset = theirs - (sent + rtt / 2.0);
        if best.is_none_or(|(_, kept)| rtt < kept) {
            best = Some((offset, rtt));
        }
    }
    Ok(best.expect("five reads"))
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
        if facts.get("disk_rotational") == Some("1") {
            warnings.push(
                "a rotating data disk: a group commits at its median replica's fsync, so it gates every group it follows".into(),
            );
        }
        let available = facts.number("mem_available_kb").unwrap_or(0);
        let cap = size_kb(host.memory_max(harness)).unwrap_or(0);
        if available < cap {
            warnings.push(format!(
                "{} MiB free, under its cap of {}",
                available >> 10,
                host.memory_max(harness)
            ));
        }
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

/// Probe and judge every host of `inventory`, in parallel: the facts in
/// inventory order. A host that cannot be reached is refused.
pub fn check(inventory: &Inventory) -> Vec<Facts> {
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
            (Some(disk), _) => format!("{disk} ({})", host.get("disk_transport").unwrap_or("ssd")),
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
    use super::{Facts, judge, kernel_at_least, size_kb};
    use crate::inventory::Inventory;

    fn inventory() -> Inventory {
        Inventory::parse(
            r#"
            [[host]]
            name = "a"
            ssh = "me@10.0.0.1"
            address = "10.0.0.1"
            role = "node"
            dir = "/data"
            ingress = 7001
            peer = 7101
            [[host]]
            name = "b"
            ssh = "localhost"
            address = "127.0.0.1"
            role = "node"
            dir = "/b"
            ingress = 7002
            peer = 7102
            [[host]]
            name = "c"
            ssh = "localhost"
            address = "127.0.0.1"
            role = "node"
            dir = "/c"
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
