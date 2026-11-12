//! Personal agents (`light-node.md` §3.3–§3.7) at scale: `N` agents, each
//! with `Personal` installed and assigned by a home's stand-in (the `home`
//! test actor, in an agent of its own granted the role `homes`) to a test
//! device whose sync and admin keys the harness derives from the seed.
//! Each device then wakes every period, a new session each time, and sends
//! `alive`, `since` and `push` (`load`); one agent more is filled to its
//! quota and a replica of it replaced by a spare node, which installs it
//! from a snapshot (`fill`). `Personal` admits a request only through the
//! onion: the driver key, a gateway every node lists, marks its frames
//! `Onion` as a gateway marks what its onion service received.

mod fill;
mod load;
mod onion;
mod summary;

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use vos_node::client::{Client, Operator};
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, derive_id};
use vos_wire::ingress::Response;
use vos_wire::personal::{AdminClass, Attestation, Kit, NewDevice, Policy};
use vos_wire::result::Outcome;

use crate::agents::{Mix, Placed, created, install, operators, place, read_elf};
use crate::deploy::Deployed;
use crate::hosts::wait_for;
use crate::inventory::Inventory;

pub use fill::{Fill, fill_at};
pub use load::{Plan, run_local};
pub use summary::summary;

/// The instance `Personal` and the home are installed at.
pub const INSTANCE: u32 = 1;
/// The role `Personal` declares for its home, as the install numbers it.
const HOMES_ROLE: u8 = 1;
/// Personal agents created at once, by default: each mostly waits for its
/// group's first election and its install.
pub const CREATORS: u32 = 16;
/// How long every assigned agent has to admit its device once the last
/// is created.
const ADMITTED: Duration = Duration::from_secs(300);

/// A personal agent: its id, replicas and identity, and its index, from
/// which its device's keys are derived.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub index: u64,
    pub agent: u32,
    pub replicas: Vec<u8>,
    /// The hash of its creation record, which its calls are signed for,
    /// in hex.
    pub identity: String,
}

impl Member {
    pub fn identity(&self) -> [u8; 32] {
        crate::keys::hex32(&self.identity).expect("an identity the harness wrote")
    }
}

/// The deployed space's personal agents, kept in `personal.json` beside
/// `agents.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Personals {
    pub home: Option<Placed>,
    /// The agents the load wakes.
    pub agents: Vec<Member>,
    /// The agent the fill fills, which the load leaves alone.
    pub full: Option<Member>,
    pub seed: u64,
    pub policy_ms: (u64, u64, u64, u64),
    /// When their creation started and ended, in ms since the epoch: the
    /// nodes' memory is read on either side.
    pub created_from_ms: u64,
    pub created_to_ms: u64,
    /// Agents whose device's sync key read the agent's overview through
    /// the onion once they were all created.
    pub admitted: u64,
    /// The node hosts' names, in node order.
    #[serde(default)]
    pub nodes: Vec<String>,
}

impl Personals {
    pub fn path(inventory: &Inventory) -> std::path::PathBuf {
        Deployed::dir(inventory).join("personal.json")
    }

    pub fn read(inventory: &Inventory) -> Option<Self> {
        let text = std::fs::read_to_string(Self::path(inventory)).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn write(&self, inventory: &Inventory) -> Result<(), String> {
        let path = Self::path(inventory);
        std::fs::write(&path, serde_json::to_string_pretty(self).expect("json"))
            .map_err(|error| format!("{}: {error}", path.display()))
    }

    /// Every agent, the full one last.
    fn all(&self) -> impl Iterator<Item = &Member> {
        self.agents.iter().chain(&self.full)
    }
}

pub fn method(name: &str) -> MethodId {
    MethodId(derive_id("vos/method/", name))
}

/// Agent `index`'s device's sync and admin keys.
pub fn device_keys(seed: u64, index: u64) -> (SigningKey, SigningKey) {
    let key = |part: &[u8]| {
        let mut input = b"vos-scale personal device ".to_vec();
        input.extend(part);
        input.extend(seed.to_le_bytes());
        input.extend(index.to_le_bytes());
        SigningKey::from_bytes(&vos_pvm::precompile::blake2b_256(&input))
    };
    (key(b"sync"), key(b"admin"))
}

/// Agent `index`'s device as the home assigns it: a strong admin on
/// attested hardware.
fn device(seed: u64, index: u64) -> NewDevice {
    let (sync, admin) = device_keys(seed, index);
    let mut nullifier = [0; 32];
    nullifier[..8].copy_from_slice(&index.to_le_bytes());
    NewDevice {
        sync: sync.verifying_key().to_bytes(),
        admin: admin.verifying_key().to_bytes(),
        class: AdminClass::Strong,
        attestation: Attestation {
            hardware: true,
            verified_boot: true,
        },
        nullifier,
        label: vec![1; 16],
        carried: Vec::new(),
    }
}

/// A test home's policy: delays in minutes, and the 64 MiB quota from the
/// first push, so the fill needs no re-proof.
pub fn policy() -> Policy {
    Policy {
        operation_delay_ms: 2 * 60_000,
        probation_ms: 60_000,
        confirm_window_ms: 5 * 60_000,
        bytes_new: 64 << 20,
        bytes_full: 64 << 20,
        inbox_ttl_ms: 10 * 60_000,
        slot_ttl_ms: 5 * 60_000,
        ..Policy::DEFAULT
    }
}

/// What `agents --personal` makes.
pub struct Request<'a> {
    /// The agents the load wakes; one more is made for the fill.
    pub count: u32,
    pub personal: &'a Path,
    pub home: &'a Path,
    pub seed: u64,
    pub creators: u32,
}

/// The home's call `name` on personal agent `agent`'s behalf.
fn home_call(
    client: &mut Client,
    home: AgentId,
    agent: AgentId,
    name: &str,
    arguments: impl Encode,
) -> Result<(), String> {
    let arguments = ((agent.0, INSTANCE), arguments).encode();
    match client.call(home, InstanceId(INSTANCE), method(name), &arguments) {
        Ok(Response::Ran {
            outcome: Outcome::Done(_),
            ..
        }) => Ok(()),
        other => Err(format!(
            "the home's {name} for agent {}: {other:?}",
            agent.0
        )),
    }
}

/// `agent`'s identity, the hash of its creation record, read from one of
/// its replicas: `readers` holds a client a node, each keeping its
/// connection.
fn identity(readers: &[Client], agent: AgentId, replicas: &[u8]) -> Result<[u8; 32], String> {
    let mut last = String::from("no replica answered");
    for replica in replicas {
        match readers[usize::from(*replica) - 1].identity(agent) {
            Ok(identity) => return Ok(identity),
            Err(error) => last = format!("node {replica}: {error}"),
        }
    }
    Err(format!("agent {}'s identity: {last}", agent.0))
}

/// Grant `home` the role `homes` at `agent`, at whichever replica leads it.
fn grant(
    operators: &[Operator],
    agent: AgentId,
    replicas: &[u8],
    home: AgentId,
) -> Result<(), String> {
    let mut last = String::new();
    wait_for(
        &format!("agent {} grants its home", agent.0),
        crate::agents::INSTALLED,
        Duration::from_millis(300),
        || {
            for replica in replicas {
                match operators[usize::from(*replica) - 1].grant(
                    agent,
                    Principal::Agent(home),
                    Some(HOMES_ROLE),
                ) {
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

/// Create the home and `request.count + 1` personal agents by the nodes'
/// weights, each assigned to its device; then wait for every agent to
/// admit its device through the onion.
pub fn create(inventory: &Inventory, request: &Request) -> Result<Personals, String> {
    let deployed = Deployed::read(inventory)?;
    let operators = operators(inventory, &deployed)?;
    let weights = inventory.placement_weights();
    let mut mix = Mix(request.seed ^ 0x9e75_0a1a);
    let personal = read_elf(request.personal)?;
    let home_elf = read_elf(request.home)?;
    let created_from_ms = crate::now_ms();
    let replicas = place(&weights, &mut mix);
    let home = created(operators[usize::from(replicas[0]) - 1].create_agent(replicas.clone()))?;
    install(&operators, home, &replicas, INSTANCE, &home_elf, Vec::new())?;
    eprintln!("the home: agent {} on {replicas:?}", home.0);
    let home_placed = Placed {
        agent: home.0,
        replicas,
        actor: "home".into(),
        instance: INSTANCE,
        leader: None,
    };
    let client = crate::nodes::driver_seed(inventory)?;
    let routes = deployed
        .nodes
        .iter()
        .map(|node| {
            Ok((
                crate::keys::hex32(&node.key)?,
                crate::nodes::target(node, client)?,
            ))
        })
        .collect::<Result<std::collections::HashMap<_, _>, String>>()?;
    let total = request.count + 1;
    let placements: Vec<Vec<u8>> = (0..total).map(|_| place(&weights, &mut mix)).collect();
    let next = AtomicU32::new(0);
    let made = AtomicU32::new(0);
    let mut members: Vec<Option<Member>> = vec![None; total as usize];
    let policy = policy();
    std::thread::scope(|scope| -> Result<(), String> {
        let workers: Vec<_> = (0..request.creators.clamp(1, total))
            .map(|creator| {
                let (routes, placements, deployed) = (&routes, &placements, &deployed);
                let (next, made, personal, policy) = (&next, &made, &personal, &policy);
                let home_replicas = home_placed.replicas.clone();
                scope.spawn(move || -> Result<Vec<Member>, String> {
                    let operators = crate::agents::operators(inventory, deployed)?;
                    let at_home = crate::nodes::target(
                        &deployed.nodes[usize::from(home_replicas[0]) - 1],
                        client,
                    )?;
                    let (key, _) = crate::load::user(request.seed ^ 0x40e5, u64::from(creator));
                    let mut caller = Client::new(&at_home, SigningKey::from_bytes(&key))
                        .with_routes(routes.clone());
                    let readers = deployed
                        .nodes
                        .iter()
                        .map(|node| {
                            Ok(Client::new(
                                &crate::nodes::target(node, client)?,
                                SigningKey::from_bytes(&key),
                            ))
                        })
                        .collect::<Result<Vec<_>, String>>()?;
                    let mut mine = Vec::new();
                    loop {
                        let at = next.fetch_add(1, Ordering::Relaxed);
                        if at >= total || crate::hosts::interrupted() {
                            return Ok(mine);
                        }
                        let one = (|| -> Result<Member, String> {
                            let replicas = placements[at as usize].clone();
                            let creator = &operators[usize::from(replicas[0]) - 1];
                            let agent = created(creator.create_agent(replicas.clone()))?;
                            install(
                                &operators,
                                agent,
                                &replicas,
                                INSTANCE,
                                personal,
                                vec![(b"homes".to_vec(), HOMES_ROLE)],
                            )?;
                            grant(&operators, agent, &replicas, home)?;
                            let identity = identity(&readers, agent, &replicas)?;
                            home_call(&mut caller, home, agent, "configure", *policy)?;
                            let kit = Kit {
                                entries: Vec::new(),
                                r2: vos_pvm::precompile::blake2b_256(&u64::from(at).to_le_bytes()),
                            };
                            home_call(
                                &mut caller,
                                home,
                                agent,
                                "assign",
                                (device(request.seed, u64::from(at)), kit),
                            )?;
                            Ok(Member {
                                index: u64::from(at),
                                agent: agent.0,
                                replicas,
                                identity: hex::encode(identity),
                            })
                        })();
                        let one = one.inspect_err(|_| next.store(total, Ordering::Relaxed))?;
                        mine.push(one);
                        let done = made.fetch_add(1, Ordering::Relaxed) + 1;
                        if done.is_multiple_of(500) || done == total {
                            eprintln!("{done} of {total} personal agents created and assigned");
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            for one in worker.join().expect("a creator")? {
                let at = one.index as usize;
                members[at] = Some(one);
            }
        }
        Ok(())
    })?;
    if crate::hosts::interrupted() {
        return Err("personal agents: interrupted".into());
    }
    let mut agents: Vec<Member> = members
        .into_iter()
        .map(|one| one.expect("every agent created"))
        .collect();
    let full = agents.pop();
    let mut personals = Personals {
        home: Some(home_placed),
        agents,
        full,
        seed: request.seed,
        policy_ms: (
            policy.operation_delay_ms,
            policy.probation_ms,
            policy.confirm_window_ms,
            policy.slot_ttl_ms,
        ),
        created_from_ms,
        created_to_ms: 0,
        admitted: 0,
        nodes: inventory
            .nodes()
            .iter()
            .map(|host| host.name.clone())
            .collect(),
    };
    personals.admitted = onion::admitted(
        &deployed.nodes,
        client,
        request.seed,
        personals.all(),
        ADMITTED,
    )?;
    personals.created_to_ms = crate::now_ms();
    eprintln!(
        "{} personal agents and the full one, {} admitting their device through the onion, in {:.0} s",
        personals.agents.len(),
        personals.admitted,
        (personals.created_to_ms - created_from_ms) as f64 / 1e3
    );
    personals.write(inventory)?;
    Ok(personals)
}

/// The personal agents a sessions' sample reads.
const SAMPLED: usize = 64;

/// The sessions a sample of the personal agents' leaders hold now, into
/// the run's `personal-sessions.json`: opened by the wakes, swept an hour
/// after each opened.
pub fn sample_sessions(inventory: &Inventory, run: &crate::runs::Run) -> Result<(), String> {
    let Some(personals) = Personals::read(inventory) else {
        return Ok(());
    };
    let deployed = Deployed::read(inventory)?;
    let operators = operators(inventory, &deployed)?;
    let step = (personals.agents.len() / SAMPLED).max(1);
    let sampled: Vec<serde_json::Value> = personals
        .agents
        .iter()
        .step_by(step)
        .take(SAMPLED)
        .filter_map(|member| {
            member.replicas.iter().find_map(|replica| {
                match operators[usize::from(*replica) - 1].status(AgentId(member.agent)) {
                    Ok(Response::Status(status)) if status.leads => Some(serde_json::json!({
                        "agent": member.agent,
                        "sessions": status.sessions,
                        "log_start": status.log_start,
                        "applied": status.applied,
                    })),
                    _ => None,
                }
            })
        })
        .collect();
    std::fs::write(
        run.file("personal-sessions.json"),
        serde_json::to_string_pretty(&sampled).expect("json"),
    )
    .map_err(|error| error.to_string())
}
