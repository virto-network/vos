//! `collect`: the coordinator's poll of every node's `/stats` and its
//! replicas' `/agents/*/status`, a JSON line a node every interval; then
//! each host's samples, its driver's record and its node's log, copied
//! into the run's `hosts/<name>/`.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use vos_wire::ids::AgentId;
use vos_wire::ingress::Response;

use crate::agents::Agents;
use crate::deploy::Deployed;
use crate::hosts;
use crate::inventory::{Inventory, Role};
use crate::nodes::operator;
use crate::runs::Run;

/// How long one poll's read may take at one node.
const READ: Duration = Duration::from_secs(5);

/// Poll every node each interval into the run's `nodes.jsonl`, until
/// `stop` is set.
pub fn poll(inventory: &Inventory, run: &Run, stop: &AtomicBool) -> Result<(), String> {
    let deployed = Deployed::read(inventory)?;
    let agents = Agents::read(inventory).unwrap_or_default();
    let every = Duration::from_secs(inventory.harness.every_s.max(1));
    let operators = inventory
        .nodes()
        .iter()
        .map(|host| {
            let node = deployed
                .node(host)
                .ok_or_else(|| format!("{}: not deployed", host.name))?;
            Ok((node.number, operator(inventory, node, READ)?))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let path = run.file("nodes.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let placed: Vec<_> = agents.representative.iter().chain(&agents.agents).collect();
    let mut next = Instant::now();
    while !stop.load(Ordering::Relaxed) && !hosts::interrupted() {
        for (number, operator) in &operators {
            let mut groups = serde_json::Value::Null;
            let stats = match operator.stats() {
                Ok(Response::Stats(stats)) => {
                    groups = serde_json::json!({
                        "replicas": stats.groups.replicas,
                        "leading": stats.groups.leading,
                        "terms": stats.groups.terms,
                    });
                    serde_json::Value::Object(
                        stats
                            .stages
                            .iter()
                            .map(|stage| {
                                let buckets: BTreeMap<String, u64> = stage
                                    .counts
                                    .iter()
                                    .enumerate()
                                    .filter(|(_, count)| **count > 0)
                                    .map(|(index, count)| (index.to_string(), *count))
                                    .collect();
                                (
                                    stage.name.clone(),
                                    serde_json::json!({ "total": stage.total, "buckets": buckets }),
                                )
                            })
                            .collect(),
                    )
                }
                Ok(other) => serde_json::json!({ "error": format!("{other:?}") }),
                Err(error) => serde_json::json!({ "error": error.to_string() }),
            };
            let statuses: Vec<serde_json::Value> = placed
                .iter()
                .filter(|placed| placed.replicas.contains(number))
                .map(|placed| match operator.status(AgentId(placed.agent)) {
                    Ok(Response::Status(status)) => serde_json::json!({
                        "agent": placed.agent,
                        "term": status.term,
                        "leads": status.leads,
                        "commit": status.commit,
                        "applied": status.applied,
                        "halted": status.halted,
                        "sessions": status.sessions,
                    }),
                    Ok(other) => {
                        serde_json::json!({ "agent": placed.agent, "error": format!("{other:?}") })
                    }
                    Err(error) => {
                        serde_json::json!({ "agent": placed.agent, "error": error.to_string() })
                    }
                })
                .collect();
            let line = serde_json::json!({
                "t_ms": crate::now_ms(),
                "node": number,
                "stats": stats,
                "groups": groups,
                "statuses": statuses,
            });
            writeln!(file, "{line}").map_err(|error| error.to_string())?;
        }
        next += every;
        while Instant::now() < next && !stop.load(Ordering::Relaxed) && !hosts::interrupted() {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Ok(())
}

/// Copy every host's record of `run` into the run's `hosts/<name>/`.
pub fn gather(inventory: &Inventory, run: &Run) -> Result<(), String> {
    for host in &inventory.hosts {
        let to = run.dir.join("hosts").join(&host.name);
        hosts::pull(
            host,
            &format!("{}/samples/{}.samples.jsonl", host.dir, run.id),
            &to,
        )?;
        match host.role {
            Role::Node => {
                hosts::pull(host, &format!("{}/logs/{}.node.log", host.dir, run.id), &to)?;
            }
            Role::Driver => {
                hosts::pull(
                    host,
                    &format!("{}/drive/{}.drive.jsonl", host.dir, run.id),
                    &to,
                )?;
                hosts::pull(
                    host,
                    &format!("{}/logs/{}.drive.log", host.dir, run.id),
                    &to,
                )?;
            }
        }
    }
    Ok(())
}
