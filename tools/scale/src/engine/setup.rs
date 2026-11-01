use super::*;

/// What the plan's agents are, read from the nodes, a few at once: the
/// shards, the idle agents (only when readers read them), then the
/// identity agent. Each reader keeps one connection a node: a connection
/// a read would leave one socket a read in `TIME_WAIT`, and 10^5 idle
/// agents run the driver out of local ports.
pub(super) fn agents(placed: &[&Placed], targets: &[Target]) -> Result<Vec<Agent>, String> {
    let one = |clients: &mut Vec<Option<vos_node::client::Client>>,
               placed: &Placed|
     -> Result<Agent, String> {
        let agent = AgentId(placed.agent);
        let mut last = String::from("no replica answered");
        for replica in &placed.replicas {
            let at = usize::from(*replica) - 1;
            let client = clients[at].get_or_insert_with(|| {
                vos_node::client::Client::new(
                    &targets[at],
                    ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
                )
            });
            match client.identity(agent) {
                Ok(identity) => {
                    return Ok(Agent {
                        id: agent,
                        identity,
                        replicas: placed
                            .replicas
                            .iter()
                            .map(|node| usize::from(*node) - 1)
                            .collect(),
                        paths: ["calls", "queries", "workflows"]
                            .map(|kind| format!("/agents/{}/{kind}", agent.0)),
                    });
                }
                Err(vos_node::client::ClientError::NoAgent) => {
                    last = format!("agent {}: unknown to node {replica}", agent.0)
                }
                Err(error) => last = format!("agent {} at node {replica}: {error}", agent.0),
            }
        }
        Err(last)
    };
    let readers = 16.min(placed.len()).max(1);
    let read: Vec<Vec<(usize, Result<Agent, String>)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..readers)
            .map(|reader| {
                scope.spawn(move || {
                    let mut clients: Vec<Option<vos_node::client::Client>> =
                        targets.iter().map(|_| None).collect();
                    (reader..placed.len())
                        .step_by(readers)
                        .map(|at| (at, one(&mut clients, placed[at])))
                        .collect()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("an agents' reader"))
            .collect()
    });
    let mut read: Vec<(usize, Result<Agent, String>)> = read.into_iter().flatten().collect();
    read.sort_by_key(|(at, _)| *at);
    read.into_iter().map(|(_, agent)| agent).collect()
}

pub(super) fn methods(plan: &Plan, targets: &[Target]) -> Result<Methods, String> {
    let first = plan.shards.first().ok_or("no ledger shards")?;
    let node = usize::from(first.replicas[0]);
    // A node gone since `up` (killed past its memory cap, say) refuses the
    // connection: the error names it.
    let schema = vos_node::client::schema(
        &targets[node - 1],
        AgentId(first.agent),
        InstanceId(first.instance),
    )
    .map_err(|error| format!("the shard actor's schema from node {node}: {error}"))?
    .ok_or("nothing installed in the first shard")?;
    let id = |name: &str| {
        schema
            .method_id(name)
            .ok_or_else(|| format!("the shard actor has no method {name}"))
    };
    Ok(Methods {
        transfer: id("transfer")?,
        balance: id("balance")?,
        tally: id("tally")?,
        holds_at_cut: id("holds_at_cut")?,
        set_identity: id("set_identity")?,
    })
}
