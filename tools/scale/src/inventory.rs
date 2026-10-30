//! The inventory: the hosts a run uses, each reached over ssh (or, named
//! `localhost`, run here without it), and the harness's settings.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// What a host does in a run.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// It runs one `vos` node.
    Node,
    /// It runs a load driver.
    Driver,
}

/// One entry of the inventory: a node or a driver on a host. Several
/// entries may share a host, each with its own ports and directory.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// A name unique in the inventory: its units and its run directory
    /// are named after it.
    pub name: String,
    /// How the coordinator reaches it: `user@address` for ssh, or
    /// `localhost` to run here without ssh.
    pub ssh: String,
    /// The LAN address its peers and clients reach it at.
    pub address: String,
    pub role: Role,
    /// The share of agents' replicas it takes, against the other nodes'.
    #[serde(default = "one")]
    pub weight: u32,
    /// Its directory on the data disk: the binaries, the node's data, its
    /// logs and samples.
    pub dir: String,
    /// The cores its process runs on, as `taskset -c` lists them; all
    /// when absent.
    pub cores: Option<String>,
    /// The node's ingress port (TLS, pinned by the node's key).
    #[serde(default)]
    pub ingress: u16,
    /// The node's peer port (QUIC, UDP).
    #[serde(default)]
    pub peer: u16,
    /// The node API's QUIC port (UDP): the ingress's plus 1000 when absent.
    #[serde(default)]
    pub api: u16,
    /// A memory cap for its unit, over the harness's.
    pub memory_max: Option<String>,
    /// Run on a kernel older than the JIT's 6.7, the owner having
    /// weighted it down: `check` warns instead of refusing it.
    #[serde(default)]
    pub old_kernel: bool,
}

fn one() -> u32 {
    1
}

impl Host {
    pub fn is_local(&self) -> bool {
        self.ssh == "localhost"
    }

    /// The machine it names: entries of one machine share it. A
    /// `localhost` entry is the coordinator's machine.
    pub fn machine(&self) -> &str {
        if self.is_local() {
            "localhost"
        } else {
            self.ssh.rsplit('@').next().unwrap_or(&self.ssh)
        }
    }

    /// Its node's unit, and its sampler's and driver's.
    pub fn unit(&self, part: &str) -> String {
        format!("vos-scale-{part}-{}", self.name)
    }

    pub fn ingress_url(&self) -> String {
        format!("https://{}:{}", self.address, self.ingress)
    }

    /// The node API's QUIC port.
    pub fn api_port(&self) -> u16 {
        if self.api == 0 {
            self.ingress.saturating_add(1000)
        } else {
            self.api
        }
    }

    pub fn api_url(&self) -> String {
        format!("quic://{}:{}", self.address, self.api_port())
    }

    pub fn memory_max<'a>(&'a self, harness: &'a Harness) -> &'a str {
        self.memory_max.as_deref().unwrap_or(&harness.memory_max)
    }
}

/// The harness's settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Harness {
    /// Where runs are kept on the coordinator, relative to the inventory.
    #[serde(default = "runs")]
    pub runs: PathBuf,
    /// Each unit's memory cap (systemd's `MemoryMax`).
    #[serde(default = "memory_max")]
    pub memory_max: String,
    /// The space's window length.
    #[serde(default = "window_ms")]
    pub window_ms: u64,
    /// The largest clock offset `check` admits.
    #[serde(default = "max_clock_offset_ms")]
    pub max_clock_offset_ms: u64,
    /// How often the samplers and the coordinator's poller sample.
    #[serde(default = "every_s")]
    pub every_s: u64,
    /// The longest a node or a sampler unit runs before systemd stops
    /// it: a run left up is not left up for good.
    #[serde(default = "max_run_s")]
    pub max_run_s: u64,
    /// How long a node may take to answer once its unit started: it opens
    /// every group it replicates first, so 10^5 replicas take minutes.
    #[serde(default = "start_s")]
    pub start_s: u64,
    /// A smoke on shared hardware: a node host may also hold drivers or
    /// the coordinator, which `check` otherwise refuses.
    #[serde(default)]
    pub smoke: bool,
    /// The most connections each driver keeps to each node over HTTP: the
    /// drivers' together within the nodes' `ingress_connections`.
    #[serde(default = "driver_connections")]
    pub driver_connections: usize,
    /// How the drivers reach the nodes: over the node API's QUIC, one
    /// connection a node and a stream a request (`api`, the default), or
    /// over HTTPS (`http`).
    #[serde(default)]
    pub transport: Transport,
}

/// How the drivers reach the nodes.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Api,
    Http,
}

fn runs() -> PathBuf {
    PathBuf::from("runs")
}
fn memory_max() -> String {
    "16G".into()
}
fn window_ms() -> u64 {
    vos_wire::vos_anchor::DEFAULT_LENGTH_MS
}
fn max_clock_offset_ms() -> u64 {
    100
}
fn every_s() -> u64 {
    10
}
fn driver_connections() -> usize {
    512
}
fn start_s() -> u64 {
    90
}
fn max_run_s() -> u64 {
    6 * 3_600
}

impl Default for Harness {
    fn default() -> Self {
        toml::from_str("").expect("the defaults")
    }
}

/// The inventory file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    #[serde(default)]
    pub harness: Harness,
    /// The nodes' settings, written to each node's `node.toml` as given:
    /// `vos node run --config` names them.
    #[serde(default)]
    pub node: toml::Table,
    /// The hosts a command uses: the inventory's less those excluded.
    #[serde(rename = "host")]
    pub hosts: Vec<Host>,
    /// Every host the file lists, excluded or not: `down` and `deploy`
    /// stop the harness's units on each.
    #[serde(skip)]
    pub listed: Vec<Host>,
    /// The directory the file was read from: relative paths are relative
    /// to it.
    #[serde(skip)]
    pub root: PathBuf,
    /// The file, which each run keeps a copy of.
    #[serde(skip)]
    pub path: PathBuf,
}

/// An ssh target: `localhost`, or `[user@]host` of plain characters, never
/// read as an option.
fn check_ssh(ssh: &str) -> Result<(), String> {
    let plain = ssh
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "@._-".contains(c));
    if ssh.is_empty() || ssh.starts_with('-') || !plain || ssh.matches('@').count() > 1 {
        return Err(format!("ssh {ssh:?}: `localhost` or user@host"));
    }
    Ok(())
}

/// The harness wipes inside `dir`: an absolute path of plain characters,
/// no `.` or `..` part, two parts deep at least, and not a home directory
/// itself (`deploy` refuses `$HOME` again on the host).
fn check_dir(dir: &str) -> Result<(), String> {
    let plain = dir
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/_.-".contains(c));
    let parts: Vec<&str> = dir.split('/').skip(1).collect();
    if !plain || !dir.starts_with('/') || parts.iter().any(|part| matches!(*part, "" | "." | ".."))
    {
        return Err(format!(
            "dir {dir:?}: an absolute path of letters, digits, '/', '_', '.' and '-', with no empty, '.' or '..' part"
        ));
    }
    let home = matches!(parts.as_slice(), ["root"] | ["home", _] | ["Users", _]);
    if parts.len() < 2 || home {
        return Err(format!(
            "dir {dir}: a directory of its own, deeper than {dir}, which the harness wipes inside"
        ));
    }
    Ok(())
}

/// Whether one of `a` and `b` is the other or inside it.
fn nested(a: &str, b: &str) -> bool {
    let inside =
        |outer: &str, inner: &str| inner == outer || inner.starts_with(&format!("{outer}/"));
    inside(a, b) || inside(b, a)
}

impl Inventory {
    pub fn read(path: &Path, excluded: &[String]) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let mut inventory: Inventory =
            toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        inventory.root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        inventory.path = path.to_path_buf();
        inventory.listed = inventory.hosts.clone();
        for name in excluded {
            if !inventory.hosts.iter().any(|host| &host.name == name) {
                return Err(format!("--exclude {name}: no such host"));
            }
        }
        inventory
            .hosts
            .retain(|host| !excluded.contains(&host.name));
        inventory.validate()?;
        Ok(inventory)
    }

    #[cfg(test)]
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut inventory: Inventory = toml::from_str(text).map_err(|error| error.to_string())?;
        inventory.listed = inventory.hosts.clone();
        inventory.validate()?;
        Ok(inventory)
    }

    /// The node hosts, in order: node `n` of the space is the `n`th.
    pub fn nodes(&self) -> Vec<&Host> {
        self.hosts
            .iter()
            .filter(|host| host.role == Role::Node)
            .collect()
    }

    pub fn drivers(&self) -> Vec<&Host> {
        self.hosts
            .iter()
            .filter(|host| host.role == Role::Driver)
            .collect()
    }

    pub fn runs(&self) -> PathBuf {
        self.root.join(&self.harness.runs)
    }

    fn validate(&self) -> Result<(), String> {
        let mut names = BTreeSet::new();
        let mut dirs: Vec<(&str, &str, &str)> = Vec::new();
        let mut ports = BTreeSet::new();
        for host in &self.hosts {
            let simple = |text: &str| {
                !text.is_empty()
                    && text
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            };
            if !simple(&host.name) {
                return Err(format!(
                    "host {:?}: a name of letters, digits, '-', '_' and '.'",
                    host.name
                ));
            }
            if !names.insert(&host.name) {
                return Err(format!("host {}: named twice", host.name));
            }
            check_ssh(&host.ssh).map_err(|error| format!("host {}: {error}", host.name))?;
            if host.address.parse::<std::net::IpAddr>().is_err() {
                return Err(format!(
                    "host {}: address {:?} is not an IP address",
                    host.name, host.address
                ));
            }
            check_dir(&host.dir).map_err(|error| format!("host {}: {error}", host.name))?;
            for (machine, dir, other) in &dirs {
                if *machine == host.machine() && nested(dir, &host.dir) {
                    return Err(format!(
                        "host {}: its dir {} and {other}'s {dir} are one inside the other",
                        host.name, host.dir
                    ));
                }
            }
            dirs.push((host.machine(), host.dir.as_str(), host.name.as_str()));
            if host.role == Role::Node {
                if host.ingress == 0 || host.peer == 0 {
                    return Err(format!(
                        "host {}: a node needs ingress and peer ports",
                        host.name
                    ));
                }
                if host.weight == 0 {
                    return Err(format!("host {}: a node's weight is at least 1", host.name));
                }
                for (kind, port) in [
                    ("tcp", host.ingress),
                    ("udp", host.peer),
                    ("udp", host.api_port()),
                ] {
                    if !ports.insert((&host.address, kind, port)) {
                        return Err(format!(
                            "host {}: {kind} port {port} at {} is taken by another entry",
                            host.name, host.address
                        ));
                    }
                }
            }
            if let Some(cores) = &host.cores
                && !cores
                    .chars()
                    .all(|c| c.is_ascii_digit() || ",-".contains(c))
            {
                return Err(format!(
                    "host {}: cores as `taskset -c` lists them",
                    host.name
                ));
            }
        }
        let nodes = self.nodes().len();
        if nodes < 3 {
            return Err(format!(
                "{nodes} node hosts: every agent has three replicas, on three nodes"
            ));
        }
        if nodes > usize::from(u8::MAX) {
            return Err("at most 255 nodes".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Inventory, Role};

    const THREE: &str = r#"
        [harness]
        memory_max = "4G"

        [node]
        executors = 2

        [[host]]
        name = "a"
        ssh = "localhost"
        address = "127.0.0.1"
        role = "node"
        dir = "/tmp/a"
        ingress = 7001
        peer = 7101

        [[host]]
        name = "b"
        ssh = "localhost"
        address = "127.0.0.1"
        role = "node"
        weight = 2
        dir = "/tmp/b"
        ingress = 7002
        peer = 7102

        [[host]]
        name = "c"
        ssh = "me@10.0.0.3"
        address = "10.0.0.3"
        role = "node"
        dir = "/data/vos"
        cores = "0-3"
        ingress = 7001
        peer = 7101

        [[host]]
        name = "d"
        ssh = "localhost"
        address = "127.0.0.1"
        role = "driver"
        dir = "/tmp/d"
    "#;

    #[test]
    fn an_inventory_reads_its_hosts_and_settings() {
        let inventory = Inventory::parse(THREE).unwrap();
        assert_eq!(inventory.nodes().len(), 3);
        assert_eq!(inventory.drivers()[0].name, "d");
        assert_eq!(inventory.hosts[1].weight, 2);
        assert_eq!(inventory.hosts[0].weight, 1);
        assert_eq!(inventory.hosts[3].role, Role::Driver);
        assert_eq!(inventory.harness.memory_max, "4G");
        assert_eq!(inventory.harness.max_clock_offset_ms, 100);
        assert_eq!(inventory.harness.start_s, 90);
        assert_eq!(inventory.node["executors"].as_integer(), Some(2));
        assert_eq!(inventory.hosts[0].unit("node"), "vos-scale-node-a");
        assert!(inventory.hosts[0].is_local() && !inventory.hosts[2].is_local());
    }

    #[test]
    fn the_shipped_inventories_read() {
        let example = Inventory::parse(include_str!("../inventory.example.toml")).unwrap();
        assert_eq!((example.nodes().len(), example.drivers().len()), (3, 1));
        let localhost = Inventory::parse(include_str!("../inventory.localhost.toml")).unwrap();
        assert!(localhost.hosts.iter().all(|host| host.is_local()));
    }

    #[test]
    fn clashing_or_short_inventories_are_refused() {
        let clash = THREE.replace("ingress = 7002", "ingress = 7001");
        assert!(Inventory::parse(&clash).unwrap_err().contains("taken"));
        let same_dir = THREE.replace("\"/tmp/b\"", "\"/tmp/a\"");
        assert!(Inventory::parse(&same_dir).unwrap_err().contains("dir"));
        let twice = THREE.replace("name = \"b\"", "name = \"a\"");
        assert!(Inventory::parse(&twice).unwrap_err().contains("twice"));
        let two_nodes = THREE.replace(
            "role = \"node\"\n        dir = \"/data",
            "role = \"driver\"\n        dir = \"/data",
        );
        assert!(
            Inventory::parse(&two_nodes)
                .unwrap_err()
                .contains("three replicas")
        );
        let unknown = THREE.replace("weight = 2", "wieght = 2");
        assert!(Inventory::parse(&unknown).is_err());
    }

    /// Several drivers on one machine: each its own entry, directory and
    /// units.
    #[test]
    fn a_machine_may_run_several_drivers() {
        let two = format!(
            "{THREE}\n[[host]]\nname = \"e\"\nssh = \"localhost\"\naddress = \"127.0.0.1\"\nrole = \"driver\"\ndir = \"/tmp/e\"\ncores = \"6-7\"\n"
        );
        let inventory = Inventory::parse(&two).unwrap();
        let drivers = inventory.drivers();
        assert_eq!(drivers.len(), 2);
        assert_ne!(drivers[0].unit("drive"), drivers[1].unit("drive"));
        assert_eq!(drivers[0].machine(), drivers[1].machine());
        assert_eq!(inventory.harness.driver_connections, 512);
    }

    #[test]
    fn a_dir_the_harness_could_wipe_wrongly_is_refused() {
        let with_dir =
            |dir: &str| Inventory::parse(&THREE.replace("\"/tmp/b\"", &format!("{dir:?}")));
        for dir in [
            "/",
            "/tmp",
            "/home/me",
            "/root",
            "tmp/b",
            "/tmp/../etc",
            "/tmp/./b",
            "/tmp//b",
            "/tmp/b/",
            "/tmp/b c",
            "/tmp/$HOME",
        ] {
            assert!(with_dir(dir).unwrap_err().contains("dir"), "{dir}");
        }
        // One entry's dir inside another's, on the same machine.
        assert!(
            with_dir("/tmp/a/b")
                .unwrap_err()
                .contains("one inside the other")
        );
        assert!(with_dir("/home/me/vos").is_ok());
        // The same path on another machine is another dir.
        let elsewhere = THREE.replace("\"/data/vos\"", "\"/tmp/a\"");
        assert!(Inventory::parse(&elsewhere).is_ok());
    }

    #[test]
    fn an_ssh_target_or_address_that_is_not_plain_is_refused() {
        for ssh in ["-oProxyCommand=x", "me@host;rm", "a@b@c", "", "me@ho st"] {
            let text = THREE.replace("\"me@10.0.0.3\"", &format!("{ssh:?}"));
            assert!(
                Inventory::parse(&text).unwrap_err().contains("ssh"),
                "{ssh}"
            );
        }
        let named = THREE.replace("address = \"10.0.0.3\"", "address = \"box.lan\"");
        assert!(Inventory::parse(&named).unwrap_err().contains("IP address"));
    }
}
