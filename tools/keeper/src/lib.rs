//! The home's keeper (`light-node.md` §3.3): it keeps the pool of personal
//! agents that `Homes` assigns to claims, under an operator key every node
//! of the home lists, whose client key holds the role `operator` at the
//! home's agent.
//!
//! - **Make:** each agent created on the home's replicas, `Personal`
//!   installed with its role `homes`, and that role granted to the home's
//!   agent (`Principal::Agent`), under which `Personal` takes `claim`,
//!   `configure` and `renew` (an install carries no configuration).
//!   Several at once: creating an agent mostly waits for its group's first
//!   election.
//! - **Stock:** the agents handed to `Homes` with `stock`, a page at a time;
//!   **top up** makes and stocks until the pool holds as many as asked.
//!   An agent created whose install or grant then failed is unfinished:
//!   never stocked, named in the error (`KeeperError::Unfinished`), and
//!   **finish** installs and grants it again, then stocks it.
//! - **Upgrade:** `Personal` installed anew over every agent of the pool,
//!   a batch at a time, stopping after the batch holding a refusal:
//!   its layout is append-only, so an install that refuses is the
//!   upgrade's to fix, never the next batch's to repeat.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use vos_abi::abi::Failure;
use vos_abi::ids::{AgentId, InstanceId, MethodId, Principal, derive_id};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_node::client::{Client, Operator};
use vos_wire::homes::{AgentsPage, Counts, HomesError, PAGE};
use vos_wire::ingress::{Install, Response};

/// The role byte `Personal`'s install names `homes` by.
pub const HOMES_ROLE: u8 = 1;

/// How long a new agent's command may wait for its group to elect a
/// leader.
const SETTLE: Duration = Duration::from_secs(30);

/// How long a query's answer is good for.
const QUERY_MS: u64 = 60_000;

/// The home: its agent, and the instances `Homes` and `Personal` are at.
#[derive(Clone, Copy, Debug)]
pub struct Home {
    pub agent: AgentId,
    pub homes: InstanceId,
    /// `Personal`'s instance in every pool agent.
    pub personal: InstanceId,
}

#[derive(Debug)]
pub enum KeeperError {
    /// A node's answer that is not the command's success.
    Answer { what: String, answer: String },
    /// `Homes` refused a call.
    Homes(HomesError),
    /// An upgrade a pool agent refused: the upgrade stopped at its batch.
    Refused { agent: AgentId, answer: String },
    /// Agents created whose install or grant failed, by `cause` (the
    /// first): live on their replicas, stocked by none, until `finish`.
    Unfinished {
        agents: Vec<AgentId>,
        cause: Box<KeeperError>,
    },
}

impl std::fmt::Display for KeeperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeeperError::Answer { what, answer } => write!(f, "{what}: {answer}"),
            KeeperError::Homes(error) => write!(f, "Homes refused: {error:?}"),
            KeeperError::Refused { agent, answer } => {
                write!(f, "agent {} refused the upgrade: {answer}", agent.0)
            }
            KeeperError::Unfinished { agents, cause } => {
                let ids: Vec<String> = agents.iter().map(|agent| agent.0.to_string()).collect();
                write!(f, "agents {} unfinished: {cause}", ids.join(","))
            }
        }
    }
}

impl std::error::Error for KeeperError {}

fn answer(what: impl Into<String>, answer: impl std::fmt::Debug) -> KeeperError {
    KeeperError::Answer {
        what: what.into(),
        answer: format!("{answer:?}"),
    }
}

/// The keeper of `home`'s pool: `operators` holds the operator of each node
/// by its number, from 1, and `caller` calls `Homes`. Each agent it makes
/// is replicated on `replicas`.
pub struct Keeper {
    operators: Vec<Operator>,
    caller: Mutex<Client>,
    home: Home,
    replicas: Vec<u8>,
}

impl Keeper {
    pub fn new(operators: Vec<Operator>, caller: Client, home: Home, replicas: Vec<u8>) -> Self {
        Self {
            operators,
            caller: Mutex::new(caller),
            home,
            replicas,
        }
    }

    fn operator(&self, number: u8) -> &Operator {
        &self.operators[usize::from(number) - 1]
    }

    /// `count` agents made with `Personal` from `elf`, `at_once` at a time:
    /// their ids, lowest first, and the first failure, which stops the
    /// rest. The agents made before it are whole, to stock; those it
    /// created but did not finish are the failure's
    /// (`KeeperError::Unfinished`).
    pub fn make(
        &self,
        count: usize,
        elf: &[u8],
        at_once: usize,
    ) -> (Vec<AgentId>, Result<(), KeeperError>) {
        let next = AtomicUsize::new(0);
        let made = Mutex::new(Vec::with_capacity(count));
        let unfinished = Mutex::new(Vec::new());
        let failed = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..at_once.clamp(1, count.max(1)))
                .map(|_| {
                    scope.spawn(|| -> Result<(), KeeperError> {
                        while next.fetch_add(1, Ordering::Relaxed) < count {
                            let agent = self.make_one(elf).map_err(|(created, error)| {
                                next.store(count, Ordering::Relaxed);
                                unfinished.lock().unwrap().extend(created);
                                error
                            })?;
                            made.lock().unwrap().push(agent);
                        }
                        Ok(())
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().expect("a maker"))
                .fold(Ok(()), Result::and)
        });
        let mut made = made.into_inner().unwrap();
        made.sort();
        let mut unfinished = unfinished.into_inner().unwrap();
        unfinished.sort();
        let failed = failed.map_err(|cause| {
            if unfinished.is_empty() {
                cause
            } else {
                KeeperError::Unfinished {
                    agents: unfinished,
                    cause: Box::new(cause),
                }
            }
        });
        (made, failed)
    }

    /// An agent created, then finished: on a failure, the agent if it was
    /// created.
    fn make_one(&self, elf: &[u8]) -> Result<AgentId, (Option<AgentId>, KeeperError)> {
        let creator = self.operator(self.replicas[0]);
        let agent = match creator.create_agent(self.replicas.clone()) {
            Ok(Response::Created(agent) | Response::Unconfirmed(agent)) => agent,
            other => return Err((None, answer("create", other))),
        };
        self.finish_one(agent, elf)
            .map_err(|error| (Some(agent), error))?;
        Ok(agent)
    }

    /// `agents`, unfinished, given `Personal` from `elf` and the home's
    /// grant again, then stocked: the pooled count after. Both steps are
    /// idempotent, so an agent finished already is only stocked.
    pub fn finish(&self, agents: &[AgentId], elf: &[u8]) -> Result<u32, KeeperError> {
        for agent in agents {
            self.finish_one(*agent, elf)?;
        }
        self.stock(agents)
    }

    /// `Personal` installed in `agent`, and its role `homes` granted to the
    /// home's agent.
    fn finish_one(&self, agent: AgentId, elf: &[u8]) -> Result<(), KeeperError> {
        let install = self.install(elf);
        self.at_leader(agent, "install", |operator| {
            operator.install(agent, &install)
        })?;
        let home = Principal::Agent(self.home.agent);
        self.at_leader(agent, "grant", |operator| {
            operator.grant(agent, home, Some(HOMES_ROLE))
        })
    }

    /// `Personal` from `elf` at the home's instance, its role `homes`.
    fn install(&self, elf: &[u8]) -> Install {
        Install {
            instance: self.home.personal,
            elf: elf.to_vec(),
            roles: vec![(b"homes".to_vec(), HOMES_ROLE)],
        }
    }

    /// `command` sent to `agent`'s replicas in turn until its leader runs
    /// it, while its group settles: an outcome other than `Done` is its
    /// refusal.
    fn at_leader(
        &self,
        agent: AgentId,
        what: &str,
        command: impl Fn(&Operator) -> Result<Response, vos_node::client::ClientError>,
    ) -> Result<(), KeeperError> {
        let until = Instant::now() + SETTLE;
        let mut last = String::new();
        loop {
            for replica in &self.replicas {
                match command(self.operator(*replica)) {
                    Ok(Response::Ran {
                        outcome: Outcome::Done(_),
                        ..
                    }) => return Ok(()),
                    Ok(Response::Ran { outcome, .. }) => {
                        return Err(KeeperError::Refused {
                            agent,
                            answer: format!("{what}: {outcome:?}"),
                        });
                    }
                    Ok(other) => last = format!("{other:?}"),
                    Err(error) => last = error.to_string(),
                }
            }
            if Instant::now() > until {
                return Err(answer(format!("agent {}'s {what}", agent.0), last));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Hand `agents` to `Homes`, a page at a time: the pooled count after.
    pub fn stock(&self, agents: &[AgentId]) -> Result<u32, KeeperError> {
        let mut pooled = self.tally()?.pooled;
        for page in agents.chunks(PAGE) {
            let ids: Vec<u32> = page.iter().map(|agent| agent.0).collect();
            pooled = self.call::<u32>("stock", ids)?;
        }
        Ok(pooled)
    }

    /// Make and stock agents, `batch` at a time, until the pool holds `to`:
    /// the pooled count after. A failure stops it once the agents made
    /// before it are stocked; `stock` skips an agent stocked already, so a
    /// run after a lost answer stocks again safely.
    pub fn top_up(&self, to: u32, elf: &[u8], batch: usize) -> Result<u32, KeeperError> {
        let mut pooled = self.tally()?.pooled;
        while pooled < to {
            let count = batch.max(1).min((to - pooled) as usize);
            let (made, failed) = self.make(count, elf, batch);
            let stocked = self.stock(&made);
            failed?;
            pooled = stocked?;
        }
        Ok(pooled)
    }

    /// `Personal` from `elf` installed over every agent `Homes` holds, as it
    /// lists them when the upgrade starts, `batch` at once, each batch whole
    /// before the next: the agents upgraded. A refusal stops it after its
    /// batch.
    pub fn upgrade(&self, elf: &[u8], batch: usize) -> Result<usize, KeeperError> {
        let install = self.install(elf);
        let agents = self.agents()?;
        let mut upgraded = 0;
        for chunk in agents.chunks(batch.max(1)) {
            let refusals: Vec<KeeperError> = std::thread::scope(|scope| {
                let installs: Vec<_> = chunk
                    .iter()
                    .map(|agent| {
                        let install = &install;
                        scope.spawn(move || {
                            self.at_leader(*agent, "install", |operator| {
                                operator.install(*agent, install)
                            })
                        })
                    })
                    .collect();
                installs
                    .into_iter()
                    .filter_map(|install| install.join().expect("an install").err())
                    .collect()
            });
            if let Some(refusal) = refusals.into_iter().next() {
                return Err(refusal);
            }
            upgraded += chunk.len();
        }
        Ok(upgraded)
    }

    /// Every agent `Homes` holds, by id.
    pub fn agents(&self) -> Result<Vec<AgentId>, KeeperError> {
        let mut agents = Vec::new();
        let mut after = None;
        loop {
            let page: AgentsPage = self.query("agents", after)?;
            after = page.agents.last().map(|(agent, _)| *agent);
            agents.extend(page.agents.into_iter().map(|(agent, _)| AgentId(agent)));
            if !page.more {
                return Ok(agents);
            }
        }
    }

    /// The pool's counts.
    pub fn tally(&self) -> Result<Counts, KeeperError> {
        self.query("tally", ())
    }

    fn method(name: &str) -> MethodId {
        MethodId(derive_id("vos/method/", name))
    }

    /// `Homes`' `name`, as the keeper's client calls it.
    fn call<T: Decode>(&self, name: &str, arguments: impl Encode) -> Result<T, KeeperError> {
        let response = self
            .caller
            .lock()
            .unwrap()
            .call(
                self.home.agent,
                self.home.homes,
                Self::method(name),
                &arguments.encode(),
            )
            .map_err(|error| answer(name, error))?;
        decoded(name, response)
    }

    fn query<T: Decode>(&self, name: &str, arguments: impl Encode) -> Result<T, KeeperError> {
        let not_after = vos_node::wall_clock() + QUERY_MS;
        let response = self
            .caller
            .lock()
            .unwrap()
            .query(
                self.home.agent,
                self.home.homes,
                Self::method(name),
                &arguments.encode(),
                not_after,
            )
            .map_err(|error| answer(name, error))?;
        decoded(name, response)
    }
}

/// A call's reply, or `Homes`' error.
fn decoded<T: Decode>(name: &str, response: Response) -> Result<T, KeeperError> {
    match response {
        Response::Ran {
            outcome: Outcome::Done(bytes),
            ..
        } => T::decode_exact(&bytes).ok_or_else(|| answer(name, "an undecodable reply")),
        Response::Ran {
            outcome:
                Outcome::Failed {
                    code: Failure::Handler,
                    detail,
                },
            ..
        } => match HomesError::decode_exact(&detail) {
            Some(error) => Err(KeeperError::Homes(error)),
            None => Err(answer(name, detail)),
        },
        other => Err(answer(name, other)),
    }
}
