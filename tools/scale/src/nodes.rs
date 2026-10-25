//! `up` and `down`: each node a `vos node run` in a user unit under the
//! harness's memory cap, its ingress over the node's own TLS (clients pin
//! its key; the harness makes no certificates), with a sampler beside it;
//! stopped by their units' names.

use std::time::Duration;

use vos_node::client::{Operator, Target};
use vos_node::tls::Trust;

use crate::check::{self, Facts};
use crate::deploy::{Deployed, DeployedNode};
use crate::hosts::{self, Unit, quote};
use crate::inventory::{Host, Inventory, Role};
use crate::runs::Run;

/// How long a node may take to answer once its unit started.
const START: Duration = Duration::from_secs(90);

/// The units the harness may run on `host`.
pub fn units_of(host: &Host) -> Vec<String> {
    ["node", "sample", "drive"]
        .iter()
        .map(|part| host.unit(part))
        .collect()
}

/// Where `node`'s ingress is reached, pinned to its key.
pub fn target(node: &DeployedNode) -> Result<Target, String> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(&node.key, &mut key).map_err(|error| error.to_string())?;
    Target::new(&node.url, Trust::NodeKey(key)).map_err(|error| error.to_string())
}

/// `host`'s node's operator, by the admin token its data directory holds.
pub fn operator(host: &Host, node: &DeployedNode, answer: Duration) -> Result<Operator, String> {
    let token = hosts::run(
        host,
        &format!("cat {}/data/{}\n", quote(&host.dir), vos_node::ADMIN_TOKEN),
    )?;
    Ok(Operator::within(&target(node)?, token.trim(), answer))
}

fn node_unit<'a>(host: &'a Host, run: &Run, inventory: &'a Inventory) -> Unit<'a> {
    let dir = &host.dir;
    let listen = format!("{}:{}", host.address, host.ingress);
    let command = [
        &format!("{dir}/bin/vos"),
        "node",
        "run",
        "--data",
        &format!("{dir}/data"),
        "--listen",
        &listen,
        "--space",
        &format!("{dir}/space"),
        "--agent",
        &format!("{dir}/guests/vos-agent.elf"),
        "--config",
        &format!("{dir}/node.toml"),
        "--tls",
        "--tls-name",
        &host.address,
    ]
    .map(str::to_string)
    .to_vec();
    Unit {
        name: host.unit("node"),
        memory_max: host.memory_max(&inventory.harness),
        stdout: format!("{dir}/logs/{}.node.out", run.id),
        stderr: format!("{dir}/logs/{}.node.log", run.id),
        cores: host.cores.as_deref(),
        env: vec![("VOS_LOG", "info".into())],
        command,
    }
}

fn sampler_unit<'a>(
    host: &'a Host,
    facts: &Facts,
    run: &Run,
    inventory: &'a Inventory,
) -> Unit<'a> {
    let dir = &host.dir;
    let mut command = vec![
        format!("{dir}/bin/vos-scale"),
        "sample".into(),
        "--every".into(),
        inventory.harness.every_s.to_string(),
        "--out".into(),
        format!("{dir}/samples/{}.samples.jsonl", run.id),
    ];
    // The process it follows: the node, or the driver while it drives.
    let watched = match host.role {
        Role::Node => host.unit("node"),
        Role::Driver => host.unit("drive"),
    };
    command.extend(["--unit".into(), watched]);
    if let Some(iface) = facts.get("iface") {
        command.extend(["--iface".into(), iface.to_string()]);
    }
    if let Some(disk) = facts.get("disk") {
        command.extend(["--disk".into(), disk.to_string()]);
    }
    Unit {
        name: host.unit("sample"),
        memory_max: "256M",
        stdout: format!("{dir}/logs/sample.log"),
        stderr: format!("{dir}/logs/sample.log"),
        cores: None,
        env: Vec::new(),
        command,
    }
}

/// Start every node and every host's sampler for `run`, once each host's
/// facts pass `check` (or `force`), and wait for every node to answer
/// with its key.
pub fn up(inventory: &Inventory, run: &Run, force: bool) -> Result<(), String> {
    let deployed = Deployed::read(inventory)?;
    let facts = check::check(inventory);
    std::fs::write(
        run.file("hosts.json"),
        serde_json::to_string_pretty(&facts).expect("json"),
    )
    .map_err(|error| error.to_string())?;
    std::fs::write(
        run.file("deployed.json"),
        serde_json::to_string_pretty(&deployed).expect("json"),
    )
    .map_err(|error| error.to_string())?;
    eprint!("{}", check::table(&facts));
    if !force && facts.iter().any(|host| !host.refused.is_empty()) {
        return Err("a host is refused: fix it, exclude it, or --force".into());
    }
    for (host, facts) in inventory.hosts.iter().zip(&facts) {
        let mut script = String::new();
        if host.role == Role::Node {
            script += &node_unit(host, run, inventory).start_script();
        }
        script += &sampler_unit(host, facts, run, inventory).start_script();
        hosts::run(host, &script)?;
    }
    for host in inventory.nodes() {
        let node = deployed
            .node(host)
            .ok_or_else(|| format!("{}: not deployed", host.name))?;
        let target = target(node)?;
        hosts::wait_for(
            &format!("{} answers", host.name),
            START,
            Duration::from_millis(250),
            || match vos_node::client::node_id(&target) {
                Ok(id) if hex::encode(id.0) == node.key => Ok(true),
                Ok(id) => Err(format!(
                    "{}: answered as {}, not its key {}",
                    host.name,
                    hex::encode(id.0),
                    node.key
                )),
                Err(_) => {
                    let state = hosts::run(host, &hosts::state_script(&host.unit("node")))?;
                    match state.trim() {
                        "active" | "activating" => Ok(false),
                        other => Err(format!(
                            "{}: its node is {other}: see {}/logs/{}.node.log",
                            host.name, host.dir, run.id
                        )),
                    }
                }
            },
        )?;
        eprintln!("{}: node {} up at {}", host.name, node.number, node.url);
    }
    Ok(())
}

/// Stop every unit the harness runs on every host.
pub fn down(inventory: &Inventory) -> Result<(), String> {
    std::thread::scope(|scope| {
        let stopped: Vec<_> = inventory
            .hosts
            .iter()
            .map(|host| scope.spawn(move || hosts::run(host, &hosts::stop_script(&units_of(host)))))
            .collect();
        stopped
            .into_iter()
            .try_for_each(|thread| thread.join().expect("a stop thread").map(drop))
    })
}
