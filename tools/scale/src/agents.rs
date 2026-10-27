//! `agents`: the load model's agents, each created on three nodes drawn by
//! the nodes' weights with the shard actor installed: `K` ledger shards
//! and `I` idle agents; the stand-in identity agent on every node, its `U`
//! rows written; with `--representative`, the space's representative
//! first, on three founding nodes by weight. The agents are kept in the
//! deployed space's `agents.json` for the drivers.

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use vos_node::client::{Client, Operator};
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::ingress::{Install, Response};
use vos_wire::result::Outcome;

use crate::deploy::Deployed;
use crate::hosts::wait_for;
use crate::inventory::{Host, Inventory};
use crate::nodes::{operator, target};

/// Identity rows a call writes: the shard actor's most.
const FILL: u64 = 1_000;

/// Agents created at once, by default.
pub const CREATORS: u32 = 16;

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
    /// Its leader as last read, by node number.
    #[serde(default)]
    pub leader: Option<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Agents {
    pub representative: Option<Placed>,
    /// The ledger shards the load calls.
    pub agents: Vec<Placed>,
    /// Agents created and installed, and never called.
    #[serde(default)]
    pub idle: Vec<Placed>,
    /// The stand-in identity agent, replicated on every node, and its
    /// rows.
    #[serde(default)]
    pub identity: Option<Placed>,
    #[serde(default)]
    pub identity_rows: u64,
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
#[derive(Clone, Copy)]
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
            operator(inventory, node, ANSWER)
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

/// Write the identity agent's rows `0..rows`, [`FILL`] a call, from a few
/// clients at once.
fn fill_identities(
    deployed: &Deployed,
    identity: &Placed,
    rows: u64,
    seed: u64,
) -> Result<(), String> {
    let agent = AgentId(identity.agent);
    let instance = InstanceId(identity.instance);
    let target = target(&deployed.nodes[usize::from(identity.replicas[0]) - 1])?;
    // The install is answered by one replica; this one may apply it later.
    let schema = installed(INSTALLED, Duration::from_millis(200), || {
        vos_node::client::schema(&target, agent, instance).map_err(|error| error.to_string())
    })
    .map_err(|error| format!("the identity agent: {error}"))?;
    let method = schema
        .method_id("fill_identities")
        .ok_or("the shard actor has no fill_identities")?;
    let calls = rows.div_ceil(FILL);
    let writers = calls.min(8);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..writers)
            .map(|writer| {
                let target = target.clone();
                scope.spawn(move || -> Result<(), String> {
                    let (key, _) = crate::load::user(seed ^ 0xf111, writer);
                    let mut client = Client::new(&target, SigningKey::from_bytes(&key));
                    for call in (writer..calls).step_by(writers as usize) {
                        let start = call * FILL;
                        let count = FILL.min(rows - start) as u32;
                        let arguments = [&start.to_le_bytes()[..], &count.to_le_bytes()].concat();
                        match client.call(agent, instance, method, &arguments) {
                            Ok(Response::Ran {
                                outcome: Outcome::Done(_),
                                ..
                            }) => {}
                            other => {
                                return Err(format!("identity rows from {start}: {other:?}"));
                            }
                        }
                    }
                    Ok(())
                })
            })
            .collect();
        handles
            .into_iter()
            .try_for_each(|handle| handle.join().expect("a writer"))
    })
}

/// What `read` gives once it gives something: an install's schema, at a
/// replica that may apply the install after another answered it.
fn installed<T>(
    limit: Duration,
    every: Duration,
    mut read: impl FnMut() -> Result<Option<T>, String>,
) -> Result<T, String> {
    let mut found = None;
    wait_for("its install applied", limit, every, || {
        found = read()?;
        Ok(found.is_some())
    })?;
    Ok(found.expect("found once the wait ends"))
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
    /// Ledger shards, `K`.
    pub count: u32,
    /// Idle agents, `I`.
    pub idle: u32,
    /// The identity agent's rows, `U`; none without one.
    pub identity_rows: u64,
    pub actor: &'a Path,
    pub instance: u32,
    /// The representative's ELF, to create and install it first.
    pub representative: Option<&'a Path>,
    pub seed: u64,
    /// Agents created at once.
    pub creators: u32,
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
            leader: None,
        });
    }
    let elf = read_elf(request.actor)?;
    let actor = request
        .actor
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let place_one = |operators: &[Operator], replicas: Vec<u8>| -> Result<Placed, String> {
        let creator = &operators[usize::from(replicas[0]) - 1];
        let agent = created(creator.create_agent(replicas.clone()))?;
        install(operators, agent, &replicas, request.instance, &elf)?;
        Ok(Placed {
            agent: agent.0,
            replicas,
            actor: actor.clone(),
            instance: request.instance,
            leader: None,
        })
    };
    let total = request.count + request.idle;
    // Placed in order from the seed, then created a few at once: each
    // agent's creation mostly waits for its group's first election.
    let placements: Vec<Vec<u8>> = (0..total).map(|_| place(&weights, &mut mix)).collect();
    let made = AtomicU32::new(0);
    let next = AtomicU32::new(0);
    let mut placed: Vec<Option<Placed>> = vec![None; total as usize];
    std::thread::scope(|scope| -> Result<(), String> {
        let workers: Vec<_> = (0..request.creators.max(1).min(total.max(1)))
            .map(|_| {
                scope.spawn(|| -> Result<Vec<(u32, Placed)>, String> {
                    let operators = crate::agents::operators(inventory, &deployed)?;
                    let mut mine = Vec::new();
                    loop {
                        let at = next.fetch_add(1, Ordering::Relaxed);
                        if at >= total || crate::hosts::interrupted() {
                            return Ok(mine);
                        }
                        let one = place_one(&operators, placements[at as usize].clone());
                        let one = one.inspect_err(|_| next.store(total, Ordering::Relaxed))?;
                        mine.push((at, one));
                        let done = made.fetch_add(1, Ordering::Relaxed) + 1;
                        if done.is_multiple_of(100) || done == total {
                            eprintln!(
                                "{done} of {total} agents created ({} shards, {} idle)",
                                request.count, request.idle
                            );
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            for (at, one) in worker.join().expect("a creator")? {
                placed[at as usize] = Some(one);
            }
        }
        Ok(())
    })?;
    if crate::hosts::interrupted() {
        return Err("agents: interrupted".into());
    }
    for (at, one) in placed.into_iter().enumerate() {
        let one = one.expect("every agent created");
        if (at as u32) < request.count {
            agents.agents.push(one);
        } else {
            agents.idle.push(one);
        }
    }
    if request.identity_rows > 0 {
        let every: Vec<u8> = (1..=hosts.len() as u8).collect();
        let identity = place_one(&operators, every)?;
        fill_identities(&deployed, &identity, request.identity_rows, request.seed)?;
        eprintln!(
            "the identity agent: agent {} on every node, {} rows",
            identity.agent, request.identity_rows
        );
        agents.identity = Some(identity);
        agents.identity_rows = request.identity_rows;
    }
    agents.write(inventory)?;
    Ok(agents)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Mix, installed, place};

    /// A replica that has not applied the install yet is read again.
    #[test]
    fn an_install_is_read_again_until_applied() {
        let mut reads = 0;
        let schema = installed(Duration::from_secs(5), Duration::from_millis(1), || {
            reads += 1;
            Ok((reads == 3).then_some("schema"))
        });
        assert_eq!(schema, Ok("schema"));
        assert_eq!(reads, 3);
        let never: Result<(), String> =
            installed(Duration::from_millis(20), Duration::from_millis(1), || {
                Ok(None)
            });
        assert!(never.unwrap_err().contains("not within"));
    }

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
