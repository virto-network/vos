//! The node's own API: its counters, its agents created, replaced and
//! called, their state, and its ingress served.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use vos_pvm::pool::CodeHash;
use vos_raft::Role;
use vos_wire::Decode;
use vos_wire::batch::{Admin, Message, Request};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::ingress::{Grant, NodeId};
use vos_wire::peer::{NodeNumber, Placement};
use vos_wire::records::unstored;
use vos_wire::result::Outcome;

use super::open::write_token;
use super::{ADMIN_TOKEN, CallError, Error, Inner, Node, Pending, ReplaceError, Reply};
use crate::queries::Asked;
use crate::store::Fjall;
use crate::{lock, random};

impl Inner {
    /// This node's replica of `agent`, if it runs one: its Raft state, or
    /// `Unavailable` if the store cannot be read.
    pub(crate) fn replica_status(&self, agent: AgentId) -> vos_wire::ingress::Response {
        use vos_wire::ingress::Response;
        let Some(run) = self.run(agent) else {
            return Response::NoAgent;
        };
        let state = run.shared.state();
        let snapshot = self.store.snapshot();
        // No count is none held; one that does not read is no answer.
        let sessions = match snapshot.get(agent, &vos_wire::keys::live_sessions()) {
            Ok(None) => Some(0),
            Ok(Some(bytes)) => unstored(&bytes)
                .and_then(|bytes| u64::decode(bytes).ok())
                .map(|(live, _)| live),
            Err(_) => None,
        };
        let outbox = snapshot
            .scan(agent, &vos_wire::keys::outbox_prefix(), None)
            .try_fold(0u64, |count, row| row.map(|_| count + 1));
        let (Ok(rows), Ok(last), Some(sessions), Ok(outbox)) = (
            self.store.agent_rows(agent),
            self.store.last_log_index(agent),
            sessions,
            outbox,
        ) else {
            return Response::Unavailable;
        };
        let last = last.unwrap_or(0);
        Response::Status(vos_wire::ingress::ReplicaStatus {
            term: state.term,
            leads: state.role == Role::Leader,
            leader: state.leader,
            commit: state.commit,
            applied: state.applied,
            log_start: rows.log_start,
            last_index: last.max(rows.log_start),
            halted: self.halted.load(Ordering::SeqCst),
            sessions,
            outbox,
            placement_term: self.placement(agent).map_or(0, |placement| placement.term),
        })
    }
}

impl Node {
    /// The node's identity, its public key, which its TLS presents.
    pub fn id(&self) -> NodeId {
        self.inner.node_id
    }

    /// Snapshots this node's groups switched to.
    pub fn snapshots_installed(&self) -> u64 {
        self.inner.counters.installed.load(Ordering::Relaxed)
    }

    /// Snapshot streams this node started to its followers.
    pub fn snapshots_streamed(&self) -> u64 {
        self.inner.counters.streamed.load(Ordering::Relaxed)
    }

    /// Messages this node sent toward agents on other nodes, again on
    /// rounds included.
    pub fn messages_sent_across(&self) -> u64 {
        self.inner.counters.sent_across.load(Ordering::Relaxed)
    }

    /// Messages this node relayed to their agent's leader.
    pub fn messages_relayed(&self) -> u64 {
        self.inner.counters.relayed.load(Ordering::Relaxed)
    }

    /// Frames of `class` that arrived here from other nodes; none of
    /// liveness, which are not counted.
    pub fn frames_arrived(&self, class: vos_net::Class) -> u64 {
        self.inner.counters.arrived[class as usize].load(Ordering::Relaxed)
    }

    /// Arrivals this node dropped for `refusal`.
    pub fn dropped(&self, refusal: crate::peer::Refusal) -> u64 {
        self.inner.drops.get(refusal)
    }

    /// Create an agent running the node's agent program, replicated on
    /// this node alone. Blocks until its record is durable.
    pub fn create_agent(&self) -> Result<AgentId, CallError> {
        self.create_replicated(Vec::new())
    }

    /// Create an agent replicated on `replicas`. Blocks until a majority
    /// of them hold its record.
    pub fn create_replicated(&self, replicas: Vec<NodeNumber>) -> Result<AgentId, CallError> {
        let inner = Arc::clone(&self.inner);
        smol::block_on(
            self.inner
                .runtime
                .spawn(async move { inner.create_agent(replicas).await }),
        )
    }

    /// Create the space's representative replicated on `replicas`: on the
    /// space's first founding node alone, once. Blocks until a majority of
    /// them hold its record.
    pub fn create_representative(&self, replicas: Vec<NodeNumber>) -> Result<AgentId, CallError> {
        let inner = Arc::clone(&self.inner);
        smol::block_on(
            self.inner
                .runtime
                .spawn(async move { inner.create_representative(replicas).await }),
        )
    }

    /// The space's representative, when the space has a genesis.
    pub fn representative(&self) -> Option<AgentId> {
        self.inner.representative()
    }

    /// This node's anchor keys, oldest first: its node key, then each
    /// rotation's. Its leadership of the representative signs with the
    /// newest the venue lists.
    pub fn anchor_keys(&self) -> Vec<[u8; 32]> {
        self.inner.anchor_keys.public()
    }

    /// Make an anchor key, kept durably before it is returned, for the
    /// space's controller to register at the venue (`add_authority`): the
    /// node signs with it once the venue lists it, and the controller then
    /// removes the old one. [`crate::rotate_anchor_key`] makes one for a
    /// stopped node.
    pub fn rotate_anchor_key(&self) -> Result<[u8; 32], Error> {
        let inner = Arc::clone(&self.inner);
        smol::block_on(
            self.inner
                .runtime
                .spawn(async move { inner.anchor_keys.rotate(&inner.storage).await }),
        )
        .map_err(Error::Data)
    }

    /// Replace `agent`'s replica `remove` by node `add`: the replicas once
    /// the change committed.
    pub fn replace(
        &self,
        agent: AgentId,
        remove: NodeNumber,
        add: NodeNumber,
    ) -> Result<Vec<NodeNumber>, ReplaceError> {
        let inner = Arc::clone(&self.inner);
        smol::block_on(
            self.inner
                .runtime
                .spawn(async move { inner.replace(agent, remove, add).await }),
        )
    }

    /// Where `agent` runs, as this node last heard.
    pub fn placement(&self, agent: AgentId) -> Option<Placement> {
        self.inner.placement(agent)
    }

    /// This node's replica of `agent`, as the operator's status route
    /// reports it, if it runs one.
    pub fn replica(&self, agent: AgentId) -> Option<vos_wire::ingress::ReplicaStatus> {
        match self.inner.replica_status(agent) {
            vos_wire::ingress::Response::Status(status) => Some(status),
            _ => None,
        }
    }

    /// Whether this node's replica leads `agent`'s group.
    pub fn leads(&self, agent: AgentId) -> bool {
        self.inner
            .run(agent)
            .is_some_and(|run| run.shared.state().role == Role::Leader)
    }

    /// The last index this node's replica of `agent` applied.
    pub fn applied(&self, agent: AgentId) -> Option<u64> {
        Some(self.inner.run(agent)?.shared.state().applied)
    }

    /// Install a package as `instance` of `agent`: the ELF its actor's
    /// crate built, from which the node derives its programs, stored and
    /// pooled, and its roles' bytes. The install is queued and answered
    /// with its derivation, encoded.
    pub fn install(
        &self,
        agent: AgentId,
        instance: InstanceId,
        elf: &[u8],
        roles: Vec<(Vec<u8>, u8)>,
    ) -> impl Future<Output = Result<Reply, CallError>> + use<> {
        let inner = Arc::clone(&self.inner);
        let elf = elf.to_vec();
        // On the node's thread, as every queueing is.
        self.inner.runtime.spawn(async move {
            inner
                .install(agent, instance, elf, roles)
                .await
                .map(|answered| answered.reply)
        })
    }

    /// Grant `principal` a role in `agent`, or (`None`) revoke it.
    pub fn set_role(
        &self,
        agent: AgentId,
        principal: Principal,
        role: Option<u8>,
    ) -> impl Future<Output = Result<Reply, CallError>> + use<> {
        let inner = Arc::clone(&self.inner);
        self.inner.runtime.spawn(async move {
            inner
                .admin(agent, Admin::SetRole(Grant { principal, role }))
                .await
                .map(|answered| answered.reply)
        })
    }

    /// A client request to `agent`, answered once its step is applied here.
    pub fn call(
        &self,
        agent: AgentId,
        request: Request,
    ) -> impl Future<Output = Result<Reply, CallError>> + use<> {
        let call = self.inner.call(agent, request);
        async move { call.await.map(|answered| answered.reply) }
    }

    /// Run a query handler on `agent`'s applied state. It never enters the
    /// log; its time and seed are the last applied work result's.
    pub fn query(
        &self,
        agent: AgentId,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> impl Future<Output = Result<Outcome, CallError>> + use<> {
        let inner = Arc::clone(&self.inner);
        let asked = Asked {
            caller,
            instance,
            method,
            arguments,
        };
        async move { inner.query(agent, asked).await }
    }

    /// Queue a message for `target` as delivery from its sender would.
    /// Delivery orders each pair's messages; this does not, so a test can
    /// deliver out of order.
    pub fn deliver(&self, target: AgentId, message: Message) -> Result<(), CallError> {
        self.inner.push(target, Pending::Message(message))
    }

    /// How long its stages took since it started, as its operator's stats
    /// route reports them.
    pub fn stats(&self) -> vos_wire::ingress::Stats {
        self.inner.stats()
    }

    /// The node's storage, to read applied state and the log.
    pub fn store(&self) -> &Fjall {
        &self.inner.store
    }

    /// The latest root of `agent`'s committed map `map`, the node of the
    /// agent's tree at the map's prefix, the state version it holds, and a
    /// proof of `keys` against it, from one storage snapshot. Refused as
    /// building while a build is part-way through the tree and a write to
    /// the map waits.
    pub fn prove<K: AsRef<[u8]>>(
        &self,
        agent: AgentId,
        map: vos_wire::ids::MapId,
        keys: &[K],
    ) -> Result<crate::roots::Proven, crate::roots::Error> {
        crate::roots::prove(&self.inner.store.snapshot(), agent, map, keys)
    }

    /// The blobs some agent keeps here: the programs its instances run.
    pub fn pinned(&self) -> Vec<[u8; 32]> {
        self.inner.blobs.pinned().unwrap_or_default()
    }

    /// Whether the blob store holds `hash`.
    pub fn stores_blob(&self, hash: &[u8; 32]) -> bool {
        self.inner.blobs.contains(hash).unwrap_or(false)
    }

    /// Whether the machine pool holds `program`: instances of it run
    /// without loading it first.
    pub fn pooled(&self, program: &[u8; 32]) -> bool {
        self.inner
            .machines
            .pool
            .program(&CodeHash(*program))
            .is_some()
    }

    /// Serve the HTTP ingress on `address` (`127.0.0.1:0` picks a port):
    /// the address it listens on. The operator's token goes to the data
    /// directory, readable by its owner only. Without TLS, only a loopback
    /// address is served (`0.0.0.0` and `::` are not loopback).
    pub fn serve(&self, address: SocketAddr) -> Result<SocketAddr, Error> {
        let tls = match &self.ingress_tls {
            Some(tls) => Some(crate::tls::server_config(tls, &self.secret).map_err(Error::Data)?),
            None if address.ip().is_loopback() => None,
            None => {
                return Err(Error::Data(format!(
                    "{address}: plain HTTP serves loopback addresses only; give the ingress TLS"
                )));
            }
        };
        let token = random();
        write_token(&self.data.join(ADMIN_TOKEN), &token)
            .map_err(|error| Error::Data(error.to_string()))?;
        let listener = smol::block_on(smol::net::TcpListener::bind(address))
            .map_err(|error| Error::Data(error.to_string()))?;
        let local = listener
            .local_addr()
            .map_err(|error| Error::Data(error.to_string()))?;
        let ingress = crate::ingress::Ingress::new(Arc::clone(&self.inner), token);
        let (stop, stopped) = smol::channel::bounded(1);
        let task = self
            .inner
            .runtime
            .spawn(ingress.serve(listener, tls, stopped));
        *lock(&self.ingress) = Some((task, stop));
        Ok(local)
    }
}
