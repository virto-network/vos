//! An operator's commands at an agent's leader: a replica replaced, an
//! agent created, a package installed, a role granted.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_raft::Role;
use vos_wire::batch::Admin;
use vos_wire::ids::{AgentId, InstanceId, MethodId, ProgramHash};
use vos_wire::ingress::Unplaced;
use vos_wire::peer::{CreationRecord, NodeNumber, Placement};
use vos_wire::records::Derivation;

use super::{Answered, CallError, Inner, Pending, ReplaceError};
use crate::blobs::Keep;
use crate::group::Local;
use crate::storage::Change;
use crate::store::BlobRef;
use crate::timeout;

/// How long the node a replacement adds has to say it could run the
/// agent's program.
const CAPABLE: Duration = Duration::from_secs(10);
/// How long a replacement waits for its final configuration to commit.
const REPLACED: Duration = Duration::from_secs(30);
/// How long a replacement waits, once its node no longer leads, for the
/// final configuration to be announced: by this node as it steps down, or
/// by the node that took over.
const REPLACED_ELSEWHERE: Duration = Duration::from_secs(2);

impl Inner {
    /// Replace the agent's replica `remove` by node `add`, at the agent's
    /// leader: once `add` says it could run the agent's program, a joint
    /// configuration, which the core finalizes; answered with the replicas
    /// once the final configuration commits.
    pub(crate) async fn replace(
        self: &Arc<Self>,
        agent: AgentId,
        remove: NodeNumber,
        add: NodeNumber,
    ) -> Result<Vec<NodeNumber>, ReplaceError> {
        let run = self.leading(agent).await.map_err(ReplaceError::Call)?;
        let placement = self
            .placement(agent)
            .ok_or(ReplaceError::Call(CallError::NoAgent))?;
        let unplaced = |why| Err(ReplaceError::Unplaced(why));
        if placement.joint || !placement.committed {
            return unplaced(Unplaced::InProgress);
        }
        if !placement.replicas.contains(&remove) {
            return unplaced(Unplaced::NotAReplica);
        }
        if placement.replicas.contains(&add) {
            return unplaced(Unplaced::AlreadyAReplica);
        }
        if self
            .space
            .as_ref()
            .and_then(|space| space.node(add))
            .is_none()
        {
            return unplaced(Unplaced::NotInTheSpace);
        }
        if !self.could_run(agent, add, CAPABLE).await {
            return unplaced(Unplaced::CannotRun);
        }
        let mut members: Vec<NodeNumber> = placement
            .replicas
            .iter()
            .copied()
            .filter(|node| *node != remove)
            .chain([add])
            .collect();
        members.sort_unstable();
        let (answer, answered) = smol::channel::bounded(1);
        let change = Local::ChangeMembership {
            current: placement.replicas.clone(),
            members,
            answer,
        };
        if !self.to_group(agent, change) {
            return Err(ReplaceError::Call(CallError::Stopped));
        }
        let joint = match answered.recv().await {
            Ok(Ok(index)) => index,
            Ok(Err(vos_raft::core::ChangeMembershipError::NotLeader)) => {
                return Err(ReplaceError::Call(self.not_leader(&run.shared)));
            }
            Ok(Err(vos_raft::core::ChangeMembershipError::InProgress)) => {
                return unplaced(Unplaced::InProgress);
            }
            _ => return Err(ReplaceError::Call(CallError::Stopped)),
        };
        let mut until = Instant::now() + REPLACED;
        let mut leading = true;
        loop {
            if let Some(placement) = self.placement(agent)
                && placement.index > joint
                && !placement.joint
                && placement.committed
            {
                return Ok(placement.replicas);
            }
            if leading && run.shared.state().role != Role::Leader {
                leading = false;
                until = until.min(Instant::now() + REPLACED_ELSEWHERE);
            }
            if Instant::now() >= until {
                return Err(ReplaceError::TimedOut);
            }
            smol::Timer::after(Duration::from_millis(20)).await;
        }
    }

    /// Create an agent with `replicas` (this node alone when empty),
    /// running this node's agent program. Answered once a majority of the
    /// replicas hold its record durably.
    pub(crate) async fn create_agent(
        self: &Arc<Self>,
        replicas: Vec<NodeNumber>,
    ) -> Result<AgentId, CallError> {
        let mut replicas = if replicas.is_empty() {
            vec![self.number]
        } else {
            replicas
        };
        replicas.sort_unstable();
        replicas.dedup();
        let known = |node: &NodeNumber| match &self.space {
            Some(space) => space.node(*node).is_some(),
            None => *node == self.number,
        };
        if let Some(node) = replicas.iter().find(|node| !known(node)) {
            return Err(CallError::Failed(format!(
                "node {node} is not in the space"
            )));
        }
        let mut next = self.next_agent.lock().await;
        let agent = CreationRecord::agent_id(self.number, *next);
        if *next >= 1 << 24 || agent == crate::store::NODE_AGENT {
            return Err(CallError::Failed(
                "this node's agent ids are exhausted".into(),
            ));
        }
        let record = CreationRecord {
            agent,
            replicas,
            creator: self.number,
            time: (self.clock)(),
            program: self.program_hash,
            accumulate_gas: self.settings.accumulate_gas,
        };
        let placement = Placement::created(&record);
        self.storage
            .commit(vec![
                Change::Agent(record.clone()),
                Change::Placement {
                    agent,
                    placement: placement.clone(),
                },
            ])
            .await
            .map_err(CallError::Failed)?;
        *next += 1;
        drop(next);
        self.learn(record.clone(), placement);
        self.announce(agent);
        if !self.held_by_majority(&record).await {
            return Err(CallError::Unconfirmed(agent));
        }
        Ok(agent)
    }

    /// Install a package, the ELF its actor's crate built: its programs
    /// derived from it off the node's runtime thread, the actor's and a
    /// kernel per attestable method, stored and pooled, then the install
    /// queued at the leader, its entry naming their blobs. A derivation
    /// that fails, or panics, fails the install, never the node.
    pub(crate) async fn install(
        &self,
        agent: AgentId,
        instance: InstanceId,
        elf: Vec<u8>,
        roles: Vec<(Vec<u8>, u8)>,
    ) -> Result<Answered, CallError> {
        // A follower refuses before deriving anything.
        self.settled(agent).await?;
        let run = self.present(agent)?;
        if run.shared.state().role != Role::Leader {
            return Err(self.not_leader(&run.shared));
        }
        let pool = Arc::clone(&self.machines.pool);
        let pooled = self
            .executors
            .run(move || {
                let derived = vos_pvm_compiler::derive(&elf)
                    .map_err(|error| CallError::Failed(format!("the package: {error}")))?;
                let mut stored = Vec::new();
                let mut pooled = |blob: Vec<u8>| -> Result<ProgramHash, CallError> {
                    let hash = pool
                        .install(&blob)
                        .map_err(|error| CallError::Failed(format!("{error:?}")))?;
                    let reference = BlobRef {
                        hash: hash.0,
                        len: blob.len() as u64,
                    };
                    stored.push((reference, Arc::new(blob)));
                    Ok(ProgramHash(hash.0))
                };
                let derivation = Derivation::new(
                    &elf,
                    &derived.actor,
                    derived
                        .kernels
                        .iter()
                        .map(|(method, kernel)| (MethodId(*method), kernel.as_slice())),
                    derived.transpiler_version,
                );
                pooled(derived.actor)?;
                for (_, kernel) in derived.kernels {
                    pooled(kernel)?;
                }
                Ok((derivation, stored))
            })
            .await
            .map_err(|panicked| {
                CallError::Failed(format!("deriving and storing the package: {}", panicked.0))
            })?;
        let (derivation, stored) = pooled?;
        // Stored, a blob is kept by its age until the entry names it; the
        // apply then pins it.
        let mut references = Vec::with_capacity(stored.len());
        for (reference, blob) in stored {
            self.blobs
                .put(reference, blob, Keep::Aged)
                .await
                .map_err(CallError::Failed)?;
            references.push(reference);
        }
        let admin = Admin::Install {
            instance,
            derivation,
            roles,
        };
        let (answer, reply) = smol::channel::bounded(1);
        self.push(
            agent,
            Pending::Admin {
                admin,
                answer,
                blobs: references,
            },
        )?;
        self.admin_answer(reply).await
    }

    /// A queued admin command's answer, within the node's deadline. Sent
    /// again, an admin command is safe: an install and a role overwrite.
    async fn admin_answer(
        &self,
        reply: smol::channel::Receiver<Result<Answered, CallError>>,
    ) -> Result<Answered, CallError> {
        match timeout(self.settings.answered, reply.recv()).await {
            Some(answer) => answer.map_err(|_| CallError::Stopped)?,
            None => Err(CallError::TimedOut),
        }
    }

    pub(crate) async fn admin(&self, agent: AgentId, admin: Admin) -> Result<Answered, CallError> {
        self.settled(agent).await?;
        let (answer, reply) = smol::channel::bounded(1);
        self.push(
            agent,
            Pending::Admin {
                admin,
                answer,
                blobs: Vec::new(),
            },
        )?;
        self.admin_answer(reply).await
    }
}
