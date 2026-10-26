//! `deploy`: a new space on the inventory's node hosts. The static `vos`
//! and `vos-scale` of `just release`, the agent's ELF and the nodes'
//! settings go to every host by `rsync`; each node's first run makes its
//! key; the space file lists them; the first node founds the space, and
//! its genesis goes to every node. What was deployed is kept on the
//! coordinator, in the runs directory's `deployed/`.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::hosts::{self, quote};
use crate::inventory::{Host, Inventory};

/// The artifacts a deploy ships, on the coordinator.
pub struct Artifacts {
    /// The directory holding the static `vos` and `vos-scale`.
    pub bins: PathBuf,
    /// The agent program every node runs.
    pub agent: PathBuf,
    /// The repository they were built from, for its revision.
    pub repository: PathBuf,
}

/// A node of the deployed space.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeployedNode {
    pub number: u8,
    pub name: String,
    /// Its key, in hex: clients pin its TLS to it.
    pub key: String,
    pub url: String,
    /// Its API over QUIC: `quic://address:port`.
    #[serde(default)]
    pub api: String,
}

/// What a deploy shipped, and the space it founded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Deployed {
    pub space_id: String,
    pub window_ms: u64,
    /// Where window 0 starts, in ms since the Unix epoch: by the
    /// coordinator's clock, given at the founding.
    #[serde(default)]
    pub origin_ms: u64,
    pub nodes: Vec<DeployedNode>,
    /// `vos --version`, the repository's revision, and each artifact's
    /// SHA-256.
    pub versions: serde_json::Value,
    pub at_ms: u64,
}

impl Deployed {
    pub fn dir(inventory: &Inventory) -> PathBuf {
        inventory.runs().join("deployed")
    }

    pub fn read(inventory: &Inventory) -> Result<Self, String> {
        let path = Self::dir(inventory).join("deployed.json");
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}: deploy first", path.display()))?;
        let deployed: Deployed = serde_json::from_str(&text).map_err(|error| error.to_string())?;
        let names: Vec<&str> = inventory
            .nodes()
            .iter()
            .map(|host| host.name.as_str())
            .collect();
        let deployed_names: Vec<&str> = deployed
            .nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect();
        if names != deployed_names {
            return Err(format!(
                "the space was deployed on {deployed_names:?}, the inventory names {names:?}: deploy again"
            ));
        }
        Ok(deployed)
    }

    pub fn node(&self, host: &Host) -> Option<&DeployedNode> {
        self.nodes.iter().find(|node| node.name == host.name)
    }
}

/// The public key, in hex, of the seed `seed`.
fn public(seed: &[u8; 32]) -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes(),
    )
}

/// Whether the ELF at `path` is a static x86-64 executable: no
/// interpreter among its program headers.
pub fn static_x86_64(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let field = |at: usize, len: usize| -> Result<u64, String> {
        let slice = bytes
            .get(at..at + len)
            .ok_or_else(|| format!("{}: not an ELF", path.display()))?;
        Ok(slice
            .iter()
            .rev()
            .fold(0u64, |value, byte| value << 8 | u64::from(*byte)))
    };
    if bytes.get(..4) != Some(b"\x7fELF") || bytes.get(4) != Some(&2) {
        return Err(format!("{}: not a 64-bit ELF", path.display()));
    }
    if field(0x12, 2)? != 62 {
        return Err(format!("{}: not built for x86-64", path.display()));
    }
    let (offset, size, count) = (field(0x20, 8)?, field(0x36, 2)?, field(0x38, 2)?);
    for header in 0..count {
        if field((offset + header * size) as usize, 4)? == 3 {
            return Err(format!(
                "{}: dynamically linked: build it with `just release`",
                path.display()
            ));
        }
    }
    Ok(())
}

fn sha256(path: &Path) -> String {
    Command::new("sha256sum")
        .arg(path)
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .next()
                .map(str::to_string)
        })
        .unwrap_or_default()
}

fn output_of(command: &mut Command) -> String {
    command
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default()
}

/// A first run of the node at `host`'s directory: its key, in hex. The
/// node is stopped by the PID its shell started it under.
const FIRST_RUN: &str = r#"
cd "$DIR"
timeout 60 "$DIR/bin/vos" node run --data "$DIR/data" --listen 127.0.0.1:0 --agent "$DIR/guests/vos-agent.elf" > logs/first.out 2> logs/first.log &
pid=$!
for _ in $(seq 600); do
  grep -q '^node ' logs/first.out && break
  kill -0 "$pid" 2>/dev/null || break
  sleep 0.1
done
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
key=$(grep '^node ' logs/first.out | cut -d' ' -f2 || true)
if [ -z "$key" ]; then cat logs/first.log >&2; exit 1; fi
echo "$key"
"#;

/// Take `$DIR` for the harness, its `.vos-scale` marker saying the harness
/// made it and may wipe inside it: made if absent, adopted if empty, kept if
/// it holds the marker; refused if it is `/` or `$HOME` (after links), or
/// holds anything else. Only then is the node's data wiped.
const OWN: &str = r#"
real=$(realpath -m -- "$DIR")
home=$(realpath -m -- "${HOME:-/}")
if [ "$real" = / ] || [ "$real" = "$home" ]; then
  echo "$DIR is / or the home directory: the harness wipes inside its dir" >&2; exit 1
fi
if [ -e "$DIR" ] && [ ! -f "$DIR/.vos-scale" ] && [ -n "$(ls -A -- "$DIR")" ]; then
  echo "$DIR holds files and no .vos-scale marker: give the harness a dir of its own" >&2; exit 1
fi
mkdir -p -- "$DIR"
touch -- "$DIR/.vos-scale"
rm -rf -- "$DIR/data" "$DIR/space" "$DIR/space.genesis"
mkdir -p -- "$DIR/bin" "$DIR/guests" "$DIR/logs" "$DIR/samples" "$DIR/drive"
"#;

fn prepare(host: &Host, artifacts: &Artifacts) -> Result<(), String> {
    hosts::run(host, &format!("DIR={}\n{OWN}", quote(&host.dir)))?;
    for name in ["vos", "vos-scale"] {
        hosts::push(
            host,
            &artifacts.bins.join(name),
            &format!("{}/bin/{name}", host.dir),
        )?;
    }
    hosts::push(
        host,
        &artifacts.agent,
        &format!("{}/guests/vos-agent.elf", host.dir),
    )
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}

/// Deploy a new space: every host's units stopped, its node's data
/// wiped, the artifacts shipped; the space founded.
pub fn deploy(inventory: &Inventory, artifacts: &Artifacts) -> Result<Deployed, String> {
    let vos = artifacts.bins.join("vos");
    for binary in [&vos, &artifacts.bins.join("vos-scale")] {
        static_x86_64(binary)?;
    }
    let local = Deployed::dir(inventory);
    std::fs::create_dir_all(&local).map_err(|error| format!("{}: {error}", local.display()))?;
    for stale in [
        "deployed.json",
        "space",
        "space.genesis",
        "agents.json",
        "node.toml",
    ] {
        let _ = std::fs::remove_file(local.join(stale));
    }
    // Every entry's units stop, an excluded one's too: none runs on.
    crate::nodes::down(inventory)?;
    let keys: Vec<Option<String>> = std::thread::scope(|scope| {
        let shipped: Vec<_> = inventory
            .hosts
            .iter()
            .map(|host| {
                scope.spawn(move || {
                    prepare(host, artifacts)?;
                    eprintln!("{}: shipped", host.name);
                    match host.role {
                        crate::inventory::Role::Node => {
                            let script = format!("DIR={}\n{FIRST_RUN}", quote(&host.dir));
                            Ok(Some(hosts::run(host, &script)?.trim().to_string()))
                        }
                        crate::inventory::Role::Driver => Ok(None),
                    }
                })
            })
            .collect();
        shipped
            .into_iter()
            .map(|thread| thread.join().expect("a deploy thread"))
            .collect::<Result<Vec<_>, String>>()
    })?;
    let nodes: Vec<DeployedNode> = inventory
        .hosts
        .iter()
        .zip(keys)
        .filter_map(|(host, key)| Some((host, key?)))
        .zip(1..)
        .map(|((host, key), number)| DeployedNode {
            number,
            name: host.name.clone(),
            key,
            url: host.ingress_url(),
            api: host.api_url(),
        })
        .collect();
    let space: String = nodes
        .iter()
        .zip(inventory.nodes())
        .map(|(node, host)| {
            format!(
                "{} {} {}:{} {}\n",
                node.number, node.key, host.address, host.peer, node.url
            )
        })
        .collect();
    write(&local.join("space"), &space)?;
    // The harness's keys: its operator's, which every node lists and the
    // coordinator alone holds, and its drivers', which every node's API
    // admits over QUIC.
    let operator = public(&crate::keys::seed(&local.join(crate::keys::OPERATOR))?);
    let driver = public(&crate::keys::seed(&local.join(crate::keys::DRIVER))?);
    let node_hosts = inventory.nodes();
    for host in &node_hosts {
        let mut settings = inventory.node.clone();
        settings.insert("operators".into(), vec![operator.clone()].into());
        settings.insert("gateways".into(), vec![driver.clone()].into());
        settings.insert(
            "api_listen".into(),
            format!("{}:{}", host.address, host.api_port()).into(),
        );
        let settings = toml::to_string(&settings).map_err(|error| error.to_string())?;
        let file = local.join(format!("{}.node.toml", host.name));
        write(&file, &settings)?;
        hosts::push(host, &local.join("space"), &format!("{}/space", host.dir))?;
        hosts::push(host, &file, &format!("{}/node.toml", host.dir))?;
    }
    let founder = node_hosts[0];
    let dir = quote(&founder.dir);
    // A second back, so no founder's clock within the bound sees it ahead.
    let origin_ms = crate::now_ms() - 1_000;
    let space_id = hosts::run(
        founder,
        &format!(
            "{dir}/bin/vos space up --space {dir}/space --data {dir}/data --window-ms {} --origin-ms {origin_ms}\n",
            inventory.harness.window_ms
        ),
    )?
    .trim()
    .to_string();
    hosts::pull(founder, &format!("{}/space.genesis", founder.dir), &local)?;
    for host in &node_hosts[1..] {
        hosts::push(
            host,
            &local.join("space.genesis"),
            &format!("{}/space.genesis", host.dir),
        )?;
    }
    let revision = output_of(
        Command::new("git")
            .arg("-C")
            .arg(&artifacts.repository)
            .args(["describe", "--always", "--dirty", "--abbrev=12"]),
    );
    let versions = serde_json::json!({
        "vos": output_of(Command::new(&vos).arg("--version")),
        "revision": revision,
        "sha256": {
            "vos": sha256(&vos),
            "vos-scale": sha256(&artifacts.bins.join("vos-scale")),
            "vos-agent.elf": sha256(&artifacts.agent),
        },
    });
    let deployed = Deployed {
        space_id,
        window_ms: inventory.harness.window_ms,
        origin_ms,
        nodes,
        versions,
        at_ms: crate::now_ms(),
    };
    write(
        &local.join("deployed.json"),
        &serde_json::to_string_pretty(&deployed).expect("json"),
    )?;
    Ok(deployed)
}

#[cfg(test)]
mod tests {
    use super::{OWN, static_x86_64};
    use std::path::Path;

    /// `OWN` run here on `dir`, with `home` as `$HOME`.
    fn own(dir: &Path, home: &Path) -> Result<(), String> {
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                "set -euo pipefail\nDIR={}\n{OWN}",
                crate::hosts::quote(&dir.to_string_lossy())
            ))
            .env("HOME", home)
            .output()
            .unwrap();
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).into_owned())
        }
    }

    #[test]
    fn the_harness_wipes_only_a_dir_it_owns() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        std::fs::create_dir(&home).unwrap();
        // Absent: made and marked; the node's data wiped on the next deploy.
        let fresh = root.path().join("fresh");
        own(&fresh, &home).unwrap();
        assert!(fresh.join(".vos-scale").exists() && fresh.join("bin").is_dir());
        std::fs::create_dir_all(fresh.join("data/store")).unwrap();
        own(&fresh, &home).unwrap();
        assert!(!fresh.join("data").exists());
        // Empty: adopted.
        let empty = root.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        own(&empty, &home).unwrap();
        // Holding files without the marker: refused, nothing touched.
        let taken = root.path().join("taken");
        std::fs::create_dir_all(taken.join("data")).unwrap();
        std::fs::write(taken.join("data/precious"), b"x").unwrap();
        assert!(own(&taken, &home).unwrap_err().contains("marker"));
        assert!(taken.join("data/precious").exists());
        // `$HOME`, through a link too, and `/`: refused.
        assert!(own(&home, &home).unwrap_err().contains("home"));
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&home, &link).unwrap();
        assert!(own(&link, &home).unwrap_err().contains("home"));
        assert!(own(Path::new("/"), &home).unwrap_err().contains("home"));
    }

    #[test]
    fn a_dynamic_or_foreign_binary_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("elf");
        let mut elf = vec![0u8; 0x40 + 2 * 56];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[0x12] = 62;
        elf[0x20] = 0x40;
        elf[0x36] = 56;
        elf[0x38] = 2;
        elf[0x40] = 6;
        elf[0x40 + 56] = 1;
        std::fs::write(&path, &elf).unwrap();
        static_x86_64(&path).unwrap();
        elf[0x40 + 56] = 3;
        std::fs::write(&path, &elf).unwrap();
        assert!(static_x86_64(&path).unwrap_err().contains("dynamically"));
        elf[0x12] = 183;
        std::fs::write(&path, &elf).unwrap();
        assert!(static_x86_64(&path).unwrap_err().contains("x86-64"));
        std::fs::write(&path, b"#!/bin/sh").unwrap();
        assert!(static_x86_64(&path).is_err());
    }
}
