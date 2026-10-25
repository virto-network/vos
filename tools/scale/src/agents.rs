//! `agents`: agents created on three nodes each, drawn by the nodes'
//! weights, and an actor installed in each; with `--representative`, the
//! space's representative first, on three founding nodes by weight. The
//! agents are kept in the deployed space's `agents.json` for the drivers.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vos_node::client::Operator;
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::ingress::{Install, Response};

use crate::deploy::Deployed;
use crate::hosts::wait_for;
use crate::inventory::{Host, Inventory};
use crate::nodes::operator;

/// How long an operator's command may take at one node.
const ANSWER: Duration = Duration::from_secs(30);
/// How long an agent may take to elect a leader and take its install.
const INSTALLED: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Placed {
    pub agent: u32,
    pub replicas: Vec<u8>,
    pub actor: String,
    pub instance: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Agents {
    pub representative: Option<Placed>,
    pub agents: Vec<Placed>,
}

impl Agents {
    pub fn read(inventory: &Inventory) -> Result<Self, String> {
        let path = Deployed::dir(inventory).join("agents.json");
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}: create agents first", path.display()))?;
        serde_json::from_str(&text).map_err(|error| error.to_string())
    }

    fn write(&self, inventory: &Inventory) -> Result<(), String> {
        let path = Deployed::dir(inventory).join("agents.json");
        std::fs::write(&path, serde_json::to_string_pretty(self).expect("json"))
            .map_err(|error| format!("{}: {error}", path.display()))
    }
}

/// A small deterministic generator (SplitMix64): placements are a
/// function of the seed.
pub struct Mix(pub u64);

impl Mix {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Three distinct nodes of `weights` (node `i + 1` weighs `weights[i]`),
/// each drawn with probability its weight's share of those left.
pub fn place(weights: &[u32], mix: &mut Mix) -> Vec<u8> {
    let mut left: Vec<(u8, u64)> = weights
        .iter()
        .zip(1..)
        .map(|(weight, number)| (number, u64::from(*weight)))
        .collect();
    let mut chosen = Vec::with_capacity(3);
    while chosen.len() < 3 && !left.is_empty() {
        let total: u64 = left.iter().map(|(_, weight)| weight).sum();
        let mut point = mix.next() % total;
        let at = left
            .iter()
            .position(|(_, weight)| {
                if point < *weight {
                    return true;
                }
                point -= weight;
                false
            })
            .expect("a point under the total");
        chosen.push(left.remove(at).0);
    }
    chosen.sort_unstable();
    chosen
}

/// The operators of every node, in node order.
fn operators(inventory: &Inventory, deployed: &Deployed) -> Result<Vec<Operator>, String> {
    inventory
        .nodes()
        .iter()
        .map(|host| {
            let node = deployed
                .node(host)
                .ok_or_else(|| format!("{}: not deployed", host.name))?;
            operator(host, node, ANSWER)
        })
        .collect()
}

/// Install `elf` as `instance` of `agent`, at whichever replica leads it.
fn install(
    operators: &[Operator],
    agent: AgentId,
    replicas: &[u8],
    instance: u32,
    elf: &[u8],
) -> Result<(), String> {
    let install = Install {
        instance: InstanceId(instance),
        elf: elf.to_vec(),
        roles: Vec::new(),
    };
    let mut last = String::new();
    wait_for(
        &format!("agent {} installs", agent.0),
        INSTALLED,
        Duration::from_millis(300),
        || {
            for replica in replicas {
                match operators[usize::from(*replica) - 1].install(agent, &install) {
                    Ok(Response::Ran { .. }) => return Ok(true),
                    Ok(other) => last = format!("{other:?}"),
                    Err(error) => last = error.to_string(),
                }
            }
            Ok(false)
        },
    )
    .map_err(|error| format!("{error}: {last}"))
}

fn created(answer: Result<Response, vos_node::client::ClientError>) -> Result<AgentId, String> {
    match answer.map_err(|error| error.to_string())? {
        Response::Created(agent) | Response::Unconfirmed(agent) => Ok(agent),
        other => Err(format!("{other:?}")),
    }
}

fn read_elf(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// What `agents` makes.
pub struct Request<'a> {
    pub count: u32,
    pub actor: &'a Path,
    pub instance: u32,
    /// The representative's ELF, to create and install it first.
    pub representative: Option<&'a Path>,
    pub seed: u64,
}

/// Create `request.count` agents by the nodes' weights, each with the
/// actor installed, as [`Request`] says.
pub fn create(inventory: &Inventory, request: &Request) -> Result<Agents, String> {
    let deployed = Deployed::read(inventory)?;
    let operators = operators(inventory, &deployed)?;
    let hosts: Vec<&Host> = inventory.nodes();
    let weights: Vec<u32> = hosts.iter().map(|host| host.weight).collect();
    let mut mix = Mix(request.seed);
    let mut agents = Agents::default();
    if let Some(path) = request.representative {
        let replicas = place(&weights, &mut mix);
        let agent = created(operators[0].create_representative(replicas.clone()))?;
        install(
            &operators,
            agent,
            &replicas,
            vos_wire::served::REPRESENTATIVE.0,
            &read_elf(path)?,
        )?;
        eprintln!("the representative: agent {} on {replicas:?}", agent.0);
        agents.representative = Some(Placed {
            agent: agent.0,
            replicas,
            actor: "representative".into(),
            instance: vos_wire::served::REPRESENTATIVE.0,
        });
    }
    let elf = read_elf(request.actor)?;
    let actor = request
        .actor
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    for at in 0..request.count {
        let replicas = place(&weights, &mut mix);
        let creator = &operators[usize::from(replicas[0]) - 1];
        let agent = created(creator.create_agent(replicas.clone()))?;
        install(&operators, agent, &replicas, request.instance, &elf)?;
        agents.agents.push(Placed {
            agent: agent.0,
            replicas,
            actor: actor.clone(),
            instance: request.instance,
        });
        if (at + 1).is_multiple_of(10) || at + 1 == request.count {
            eprintln!("{} of {} agents created", at + 1, request.count);
        }
    }
    agents.write(inventory)?;
    Ok(agents)
}

#[cfg(test)]
mod tests {
    use super::{Mix, place};

    #[test]
    fn replicas_are_three_distinct_nodes_drawn_by_weight() {
        let weights = [1, 1, 2, 4];
        let mut mix = Mix(7);
        let mut counts = [0u32; 4];
        for _ in 0..4_000 {
            let replicas = place(&weights, &mut mix);
            assert_eq!(replicas.len(), 3);
            assert!(replicas.windows(2).all(|pair| pair[0] < pair[1]));
            for replica in replicas {
                counts[usize::from(replica) - 1] += 1;
            }
        }
        // Three of four nodes hold each agent: the heavier a node, the more
        // agents it holds, the heaviest nearly all.
        assert!(counts[3] > 3_600, "{counts:?}");
        assert!(
            counts[3] > counts[2] && counts[2] > counts[0].max(counts[1]),
            "{counts:?}"
        );
        assert_eq!(place(&[1, 1, 1], &mut Mix(1)), vec![1, 2, 3]);
        assert_eq!(place(&weights, &mut Mix(9)), place(&weights, &mut Mix(9)));
    }
}
