//! Node-owned production reconciliation for authenticated clean Agent routes.
//!
//! The installed system authority is the only managed inventory source. Its
//! own protected install is independently root-pinned by the system bootstrap
//! owner and checked during the physical route audit. Every bounded
//! page is response-bound to a fresh authenticated query and the same durable
//! authority head is assembled completely before a physical host or supervisor
//! publication is touched.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[cfg(test)]
use super::sdk::AgentDescriptor;
#[cfg(test)]
use super::sdk::authority::MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES;
use super::sdk::authority::{
    AuthorityActorProjection, AuthorityActorTarget, AuthorityAgentProjection,
    AuthorityCredentialKind, AuthorityCredentialProjection, AuthorityCredentialStatus,
    AuthorityInventoryEntry, AuthorityInventoryProjectionPage, AuthorityProjectionHead,
    AuthorityProjectionQuery, AuthorityProjectionSelector, MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES,
};
use super::sdk::wire::CanonicalWire;
use super::sdk::{AgentId, AgentProfile, NodeId, PrincipalId};
use super::supervisor::{
    AgentRouteIdentity, AgentRouteKey, AgentRoutePublication, AgentSupervisorError,
    AgentSupervisorHandle, AgentSupervisorLimits, AgentSupervisorOwner,
};
use super::supervisor_adapters::{
    AgentAuthorityRouteProjection, AgentRouteAdapterError, AgentRouteHostAttachment,
    AgentRouteHostHandle,
};

pub(crate) const MAX_INVENTORY_AGENTS: usize = 4096;
const INITIAL_RECONCILIATION_RETRY: Duration = Duration::from_secs(1);

fn installed_local_route_matches(
    identity: Option<AgentRouteIdentity>,
    key: AgentRouteKey,
    runtime: super::sdk::DeploymentId,
    deployment: super::sdk::DeploymentId,
    program: super::sdk::ProgramId,
) -> bool {
    identity.is_some_and(|identity| {
        identity.key() == key
            && identity.runtime_deployment() == runtime
            && identity.actor_deployment() == deployment
            && identity.actor_program() == program
            && identity.profile() == AgentProfile::Local
    })
}

fn completed_local_publication_matches(
    previous: Option<(super::sdk::Hash, AuthorityProjectionHead)>,
    acknowledgement: super::sdk::Hash,
    accepted_head: Option<AuthorityProjectionHead>,
    had_local_attachment: bool,
) -> bool {
    had_local_attachment
        && previous
            .is_some_and(|(prior, head)| prior == acknowledgement && Some(head) == accepted_head)
}

type CompletedLocalInstall = (
    super::sdk::Hash,
    AuthorityProjectionHead,
    AgentRouteIdentity,
);

fn completed_local_install_matches(
    previous: Option<CompletedLocalInstall>,
    acknowledgement: super::sdk::Hash,
    accepted_head: Option<AuthorityProjectionHead>,
    had_local_attachment: bool,
    identity: Option<AgentRouteIdentity>,
) -> bool {
    previous.is_some_and(|(ack, head, route)| {
        completed_local_publication_matches(
            Some((ack, head)),
            acknowledgement,
            accepted_head,
            had_local_attachment,
        ) && identity == Some(route)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentProductionOwnerError {
    ShutdownRequested,
    InvalidConfiguration,
    Authentication,
    ProjectionTransport,
    ProjectionNotReady,
    ProjectionBusy,
    InvalidProjection,
    RevokedCredential,
    WrongCredentialKind,
    InventoryLimit,
    InconsistentHead,
    StaleHead,
    ConflictingHead,
    MissingSystemAgent,
    InvalidSystemAgent,
    DuplicateHost,
    Adapter(AgentRouteAdapterError),
    Supervisor(AgentSupervisorError),
    Lifecycle(super::shared_host::SharedAgentHostError),
}

impl fmt::Display for AgentProductionOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "clean Agent production owner failed: {self:?}")
    }
}

impl std::error::Error for AgentProductionOwnerError {}

impl From<AgentSupervisorError> for AgentProductionOwnerError {
    fn from(value: AgentSupervisorError) -> Self {
        Self::Supervisor(value)
    }
}

impl From<AgentRouteAdapterError> for AgentProductionOwnerError {
    fn from(value: AgentRouteAdapterError) -> Self {
        Self::Adapter(value)
    }
}

/// Supplies a fully authenticated, response-bound authority query. Concrete
/// API and SSH authentication remain owned by their existing ingress layers;
/// the route owner neither accepts raw bearer material nor duplicates them.
pub trait AuthorityProjectionQueryAuthenticator: Send {
    fn expected_kind(&self) -> AuthorityCredentialKind;

    fn authenticate(
        &mut self,
        authority: AuthorityActorTarget,
        selector: AuthorityProjectionSelector,
    ) -> Result<AuthorityProjectionQuery, AgentProductionOwnerError>;
}

trait AuthorityProjectionTransport: Send {
    fn target(&self) -> AuthorityActorTarget;

    fn dispatch(
        &mut self,
        query: AuthorityProjectionQuery,
    ) -> Result<Vec<u8>, AgentProductionOwnerError>;
}

struct SystemAgentProjectionTransport {
    target: AuthorityActorTarget,
    handle: AgentRouteHostHandle,
}

fn projection_transport_error(
    error: super::supervisor::AgentRouteError,
) -> AgentProductionOwnerError {
    tracing::debug!(?error, "Authority inventory transport failed");
    match error {
        super::supervisor::AgentRouteError::NotReady => {
            AgentProductionOwnerError::ProjectionNotReady
        }
        super::supervisor::AgentRouteError::Busy => AgentProductionOwnerError::ProjectionBusy,
        _ => AgentProductionOwnerError::ProjectionTransport,
    }
}

impl AuthorityProjectionTransport for SystemAgentProjectionTransport {
    fn target(&self) -> AuthorityActorTarget {
        self.target
    }

    fn dispatch(
        &mut self,
        query: AuthorityProjectionQuery,
    ) -> Result<Vec<u8>, AgentProductionOwnerError> {
        if query.authority != self.target
            || query.recovery.is_some()
            || query.validate_shape().is_err()
        {
            return Err(AgentProductionOwnerError::Authentication);
        }
        self.handle
            .invoke_authority_observation(query)
            .map_err(projection_transport_error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AgentAuthorityInventory {
    head: AuthorityProjectionHead,
    principal: PrincipalId,
    agents: Vec<AgentAuthorityRouteProjection>,
}

trait AuthorityInventorySource: Send {
    fn set_shutdown_signal(&mut self, shutdown: Arc<AtomicBool>);
    fn load_inventory(&mut self) -> Result<AgentAuthorityInventory, AgentProductionOwnerError>;
}

struct CleanAuthorityProjectionClient {
    transport: Box<dyn AuthorityProjectionTransport>,
    authenticator: Box<dyn AuthorityProjectionQueryAuthenticator>,
    inventory: Option<(AuthorityCredentialProjection, AgentAuthorityInventory)>,
    shutdown: Option<Arc<AtomicBool>>,
}

impl CleanAuthorityProjectionClient {
    fn new(
        transport: Box<dyn AuthorityProjectionTransport>,
        authenticator: Box<dyn AuthorityProjectionQueryAuthenticator>,
    ) -> Self {
        Self {
            transport,
            authenticator,
            inventory: None,
            shutdown: None,
        }
    }

    fn check_shutdown(&self) -> Result<(), AgentProductionOwnerError> {
        if self
            .shutdown
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            Err(AgentProductionOwnerError::ShutdownRequested)
        } else {
            Ok(())
        }
    }

    fn query<T: CanonicalWire + PartialEq>(
        &mut self,
        selector: AuthorityProjectionSelector,
    ) -> Result<(AuthorityProjectionQuery, T), AgentProductionOwnerError> {
        let started = Instant::now();
        self.check_shutdown()?;
        tracing::debug!(?selector, "Authority inventory query started");
        // Observations retain no invocation/result custody. Every attempt,
        // including a retry of the same page, signs a fresh nondelegated query.
        let query = self
            .authenticator
            .authenticate(self.transport.target(), selector)?;
        if query.authority != self.transport.target()
            || query.selector != selector
            || query.recovery.is_some()
            || query.validate_shape().is_err()
        {
            return Err(AgentProductionOwnerError::Authentication);
        }
        self.check_shutdown()?;
        let bytes = self.transport.dispatch(query.clone())?;
        // Never start another page or publish a partially collected inventory
        // after shutdown, even when the observation itself succeeded.
        self.check_shutdown()?;
        tracing::debug!(
            ?selector,
            request = ?query.commitment(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "Authority inventory query dispatch complete"
        );
        let response =
            T::decode(&bytes).map_err(|_| AgentProductionOwnerError::InvalidProjection)?;
        if response.encode().ok().as_deref() != Some(bytes.as_slice()) {
            return Err(AgentProductionOwnerError::InvalidProjection);
        }
        Ok((query, response))
    }

    fn inventory_page(
        &mut self,
        after: Option<super::sdk::authority::AuthorityInventoryCursor>,
        known_head: Option<AuthorityProjectionHead>,
    ) -> Result<AuthorityInventoryProjectionPage, AgentProductionOwnerError> {
        let (query, page): (_, AuthorityInventoryProjectionPage) =
            self.query(AuthorityProjectionSelector::Inventory {
                after,
                limit: MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES as u16,
                known_head,
            })?;
        if page.credential.query != query || page.validate_shape().is_err() {
            return Err(AgentProductionOwnerError::InvalidProjection);
        }
        if page.credential.status != AuthorityCredentialStatus::Active {
            return Err(AgentProductionOwnerError::RevokedCredential);
        }
        if page.credential.kind != self.authenticator.expected_kind() {
            return Err(AgentProductionOwnerError::WrongCredentialKind);
        }
        Ok(page)
    }
}

/// Compare complete freshly authenticated claims, not a head or Principal alone.
/// Nonces, page cursors and signatures vary across calls; their exact query
/// binding is checked separately before this comparison.
pub(crate) fn same_inventory_claims(
    left: &AuthorityCredentialProjection,
    right: &AuthorityCredentialProjection,
) -> bool {
    if left.query.authority != right.query.authority
        || left.query.credential != right.query.credential
    {
        return false;
    }
    let mut normalized = left.clone();
    normalized.query = right.query.clone();
    normalized == *right
}

struct PendingInventoryAgent {
    row: AuthorityAgentProjection,
    replicas: Vec<super::sdk::AgentReplica>,
    actors: Vec<AuthorityActorProjection>,
}

impl PendingInventoryAgent {
    fn finish(self) -> Result<AgentAuthorityRouteProjection, AgentProductionOwnerError> {
        let descriptor = self
            .row
            .reconstruct_descriptor(self.replicas)
            .map_err(|_| AgentProductionOwnerError::InvalidProjection)?;
        AgentAuthorityRouteProjection::new(self.row.replica_generation, descriptor, self.actors)
            .map_err(|_| AgentProductionOwnerError::InvalidProjection)
    }
}

#[derive(Default)]
pub(crate) struct InventoryAssembly {
    agents: Vec<AgentAuthorityRouteProjection>,
    pending: Option<PendingInventoryAgent>,
}

impl InventoryAssembly {
    pub(crate) fn push(
        &mut self,
        entry: AuthorityInventoryEntry,
    ) -> Result<(), AgentProductionOwnerError> {
        match entry {
            AuthorityInventoryEntry::Agent(row) => {
                if self.agents.len() + usize::from(self.pending.is_some()) >= MAX_INVENTORY_AGENTS {
                    return Err(AgentProductionOwnerError::InventoryLimit);
                }
                if let Some(prior) = self.pending.take() {
                    if prior.row.identity.agent >= row.identity.agent {
                        return Err(AgentProductionOwnerError::InvalidProjection);
                    }
                    self.agents.push(prior.finish()?);
                }
                self.pending = Some(PendingInventoryAgent {
                    row,
                    replicas: Vec::new(),
                    actors: Vec::new(),
                });
            }
            AuthorityInventoryEntry::Replica { agent, replica } => {
                let pending = self
                    .pending
                    .as_mut()
                    .ok_or(AgentProductionOwnerError::InvalidProjection)?;
                if agent != pending.row.identity.agent
                    || !pending.actors.is_empty()
                    || pending.replicas.len() >= usize::from(pending.row.replica_count)
                    || pending
                        .replicas
                        .last()
                        .is_some_and(|last| last.node >= replica.node)
                {
                    return Err(AgentProductionOwnerError::InvalidProjection);
                }
                pending.replicas.push(replica);
            }
            AuthorityInventoryEntry::Actor(actor) => {
                let pending = self
                    .pending
                    .as_mut()
                    .ok_or(AgentProductionOwnerError::InvalidProjection)?;
                if actor.agent != pending.row.identity.agent
                    || pending.replicas.len() != usize::from(pending.row.replica_count)
                    || pending.actors.len() >= pending.row.capabilities.max_actors as usize
                    || pending
                        .actors
                        .last()
                        .is_some_and(|last| last.entry.actor >= actor.entry.actor)
                {
                    return Err(AgentProductionOwnerError::InvalidProjection);
                }
                pending.actors.push(actor);
            }
        }
        Ok(())
    }

    pub(crate) fn finish(
        mut self,
    ) -> Result<Vec<AgentAuthorityRouteProjection>, AgentProductionOwnerError> {
        if let Some(pending) = self.pending.take() {
            self.agents.push(pending.finish()?);
        }
        Ok(self.agents)
    }
}

impl AuthorityInventorySource for CleanAuthorityProjectionClient {
    fn set_shutdown_signal(&mut self, shutdown: Arc<AtomicBool>) {
        self.shutdown = Some(shutdown);
    }

    fn load_inventory(&mut self) -> Result<AgentAuthorityInventory, AgentProductionOwnerError> {
        // A prior complete revision is only a first-page retry hint until the
        // exact fresh page authenticates its credential and unchanged head.
        // Never publish it on failure or retain partially assembled revisions.
        // Every observation attempt is independently authenticated in query().
        let previous = self.inventory.take();
        let known_head = previous
            .as_ref()
            .filter(|(credential, inventory)| {
                credential.query.authority == self.transport.target()
                    && credential.head == inventory.head
            })
            .map(|(_, inventory)| inventory.head);
        let mut page = match self.inventory_page(None, known_head) {
            Ok(page) => page,
            Err(
                error @ (AgentProductionOwnerError::ProjectionBusy
                | AgentProductionOwnerError::ProjectionNotReady),
            ) => {
                // Keep only a complete private cache hint. A failed fresh read
                // never succeeds from this cache; retry signs a new query.
                self.inventory = previous;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if let Some((credential, inventory)) = &previous {
            let same_binding = credential.query.authority == page.credential.query.authority
                && credential.query.credential == page.credential.query.credential;
            if same_binding
                && credential.head == page.credential.head
                && !same_inventory_claims(credential, &page.credential)
            {
                return Err(AgentProductionOwnerError::InconsistentHead);
            }
            if page.unchanged && same_binding && inventory.head == page.credential.head {
                let inventory = inventory.clone();
                self.inventory = Some((page.credential, inventory.clone()));
                tracing::debug!(
                    "Authority inventory reused at freshly authenticated unchanged head"
                );
                return Ok(inventory);
            }
        }
        if page.unchanged {
            // An authenticator may rotate credentials between refreshes. The
            // hint described the old cache, not this credential's visibility.
            // Fetch a full fresh view; never reuse another credential's rows.
            page = self.inventory_page(None, None)?;
        }
        let credential = page.credential.clone();
        let mut assembly = InventoryAssembly::default();
        // Same declared aggregate capacity as the former per-Agent loaders.
        // Every nonterminal canonical page advances at least one row.
        let maximum_rows = MAX_INVENTORY_AGENTS.saturating_mul(
            1 + super::sdk::MAX_AGENT_REPLICAS
                + super::sdk::RuntimeCapabilities::STANDARD_MAX_ACTORS as usize,
        );
        let mut rows = 0usize;
        loop {
            if !same_inventory_claims(&credential, &page.credential) || page.unchanged {
                return Err(AgentProductionOwnerError::InconsistentHead);
            }
            rows = rows
                .checked_add(page.entries.len())
                .filter(|rows| *rows <= maximum_rows)
                .ok_or(AgentProductionOwnerError::InventoryLimit)?;
            for entry in page.entries {
                assembly.push(entry)?;
            }
            match page.next {
                Some(next) => page = self.inventory_page(Some(next), None)?,
                None => break,
            }
        }
        let inventory = AgentAuthorityInventory {
            head: credential.head,
            principal: credential.principal,
            agents: assembly.finish()?,
        };
        self.inventory = Some((credential, inventory.clone()));
        Ok(inventory)
    }
}

/// Shared source-test transport fixture; never used to authenticate production
/// data. Mirrors the public stream shape without decoding runtime-private state.
#[cfg(test)]
pub(crate) fn inventory_page_fixture(
    query: AuthorityProjectionQuery,
    head: AuthorityProjectionHead,
    principal: PrincipalId,
    descriptors: &[AgentDescriptor],
    actors: &[AuthorityActorProjection],
    page_cap: usize,
) -> Result<Vec<u8>, AgentProductionOwnerError> {
    use super::sdk::authority::{AuthorityBuiltinRole, AuthorityIngressAuthentication};
    let AuthorityProjectionSelector::Inventory {
        after,
        limit,
        known_head,
    } = query.selector
    else {
        return Err(AgentProductionOwnerError::InvalidProjection);
    };
    let unchanged = after.is_none() && known_head == Some(head);
    let kind = match query.authentication {
        AuthorityIngressAuthentication::ApiCredentialSignature { .. } => {
            AuthorityCredentialKind::Api
        }
        AuthorityIngressAuthentication::SshNodeAttestation { .. } => AuthorityCredentialKind::Ssh,
    };
    let mut page = AuthorityInventoryProjectionPage {
        credential: AuthorityCredentialProjection {
            query,
            head,
            principal,
            status: AuthorityCredentialStatus::Active,
            kind,
            builtin_role: AuthorityBuiltinRole::Admin,
            management_request_high_water: 0,
            operation_request_high_water: 0,
            admin_request_high_water: 0,
            space_roles: Vec::new(),
            actor_roles: Vec::new(),
            capabilities: Vec::new(),
        },
        unchanged,
        entries: Vec::new(),
        next: None,
    };
    let mut more = false;
    if !unchanged {
        let mut ordered: Vec<_> = descriptors.iter().collect();
        ordered.sort_by_key(|descriptor| descriptor.identity.agent);
        let mut complex = 0;
        'agents: for descriptor in ordered
            .into_iter()
            .filter(|descriptor| after.is_none_or(|after| descriptor.identity.agent >= after.agent))
        {
            let row = AuthorityInventoryEntry::Agent(AuthorityAgentProjection {
                identity: descriptor.identity.clone(),
                creation_nonce: descriptor.creation_nonce,
                authority: descriptor.authority,
                private_recovery: descriptor.private_recovery,
                runtime_package: descriptor.runtime_package.clone(),
                runtime_contract: descriptor.runtime_contract,
                capabilities: descriptor.capabilities,
                replica_count: descriptor.replicas.len() as u16,
                replica_generation: descriptor.replica_generation(),
            });
            let mut actor_rows: Vec<_> = actors
                .iter()
                .filter(|actor| actor.agent == descriptor.identity.agent)
                .collect();
            actor_rows.sort_by_key(|actor| actor.entry.actor);
            let rows = std::iter::once(row)
                .chain(descriptor.replicas.iter().cloned().map(|replica| {
                    AuthorityInventoryEntry::Replica {
                        agent: descriptor.identity.agent,
                        replica,
                    }
                }))
                .chain(
                    actor_rows
                        .into_iter()
                        .cloned()
                        .map(AuthorityInventoryEntry::Actor),
                );
            for entry in rows.filter(|entry| after.is_none_or(|after| entry.cursor() > after)) {
                let is_complex = !matches!(entry, AuthorityInventoryEntry::Replica { .. });
                if page.entries.len() == usize::from(limit).min(page_cap)
                    || is_complex && complex == MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES
                {
                    more = true;
                    break 'agents;
                }
                complex += usize::from(is_complex);
                page.entries.push(entry);
            }
        }
    }
    loop {
        if more && page.entries.is_empty() {
            return Err(AgentProductionOwnerError::InvalidProjection);
        }
        page.next = more
            .then(|| page.entries.last().map(AuthorityInventoryEntry::cursor))
            .flatten();
        if let Ok(bytes) = page.encode() {
            return Ok(bytes);
        }
        if page.entries.pop().is_none() {
            return Err(AgentProductionOwnerError::InvalidProjection);
        }
        more = true;
    }
}

#[cfg(all(test, feature = "storage", feature = "network", target_os = "linux"))]
pub(crate) fn load_system_inventory_for_test(
    attachment: &AgentRouteHostAttachment,
    authenticator: Box<dyn AuthorityProjectionQueryAuthenticator>,
    full_refreshes: usize,
) -> Result<
    (
        AuthorityProjectionHead,
        PrincipalId,
        Vec<AgentAuthorityRouteProjection>,
    ),
    AgentProductionOwnerError,
> {
    let handle = attachment.handle();
    let target = handle
        .authority_target()
        .map_err(|_| AgentProductionOwnerError::ProjectionTransport)?;
    let mut client = CleanAuthorityProjectionClient::new(
        Box::new(SystemAgentProjectionTransport { target, handle }),
        authenticator,
    );
    let mut inventory = None;
    for _ in 0..full_refreshes {
        // Stress the public paging/retirement path beyond the journal suffix
        // capacity, independently of the unchanged-head cache optimization.
        client.inventory = None;
        let current = client.load_inventory()?;
        if inventory.as_ref().is_some_and(|prior| prior != &current) {
            return Err(AgentProductionOwnerError::InconsistentHead);
        }
        inventory = Some(current);
    }
    let inventory = inventory.ok_or(AgentProductionOwnerError::InvalidProjection)?;
    Ok((inventory.head, inventory.principal, inventory.agents))
}

enum OwnedRouteSlot {
    Empty,
    Pending(AgentRouteHostAttachment),
    Published {
        handle: AgentRouteHostHandle,
        publication: AgentRoutePublication,
    },
}

struct OwnedSharedGeneration {
    generation: crate::network::shared_agent::SharedAgentRouteHandle,
    slot: OwnedRouteSlot,
}

impl OwnedRouteSlot {
    fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }
}

/// Sole owner of the clean supervisor, authenticated inventory client, and
/// every Local/Shared/System physical worker attachment.
pub(crate) struct AgentProductionOwner {
    node: NodeId,
    system_agent: AgentId,
    supervisor: Option<AgentSupervisorOwner>,
    system: OwnedRouteSlot,
    local: OwnedRouteSlot,
    local_by_agent: Option<BTreeMap<AgentId, OwnedRouteSlot>>,
    shared: OwnedRouteSlot,
    shared_by_agent: Option<BTreeMap<AgentId, OwnedSharedGeneration>>,
    source: Box<dyn AuthorityInventorySource>,
    accepted_head: Option<AuthorityProjectionHead>,
    // A previously accepted head is an anti-rollback pin, not permission to
    // serve while a fresh inventory read is contending with retained work.
    routes_verified: bool,
    routes_need_quarantine: bool,
    // Bounded, process-local delivery deduplication only. Never used to
    // authorize management, recover an application, or restore publication.
    completed_local_publication: Option<(super::sdk::Hash, AuthorityProjectionHead)>,
    completed_local_install: Option<CompletedLocalInstall>,
    reconcile_interval: Duration,
    reconcile_after: Instant,
    lifecycle: Option<(Box<dyn super::local_lifecycle::NativeLocalLifecycle>, usize)>,
}

impl fmt::Debug for AgentProductionOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentProductionOwner")
            .field("node", &self.node)
            .field("system_agent", &self.system_agent)
            .field("accepted_head", &self.accepted_head)
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl AgentProductionOwner {
    pub(crate) fn ingress(&self) -> Result<CleanAgentIngress, AgentProductionOwnerError> {
        if !self.is_ready() {
            return Err(AgentProductionOwnerError::ProjectionNotReady);
        }
        let authority = match &self.system {
            OwnedRouteSlot::Published { handle, .. } => handle.clone(),
            _ => return Err(AgentProductionOwnerError::InvalidConfiguration),
        };
        Ok(CleanAgentIngress {
            node: self.node,
            supervisor: self.handle(),
            authority,
        })
    }
    pub(crate) fn start(
        node: NodeId,
        limits: AgentSupervisorLimits,
        system_attachment: AgentRouteHostAttachment,
        authenticator: Box<dyn AuthorityProjectionQueryAuthenticator>,
        reconcile_interval: Duration,
    ) -> Result<Self, AgentProductionOwnerError> {
        Self::start_with_lifecycle(
            node,
            limits,
            system_attachment,
            authenticator,
            reconcile_interval,
            None,
        )
    }

    pub(crate) fn start_local(
        node: NodeId,
        limits: AgentSupervisorLimits,
        lifecycle: Box<dyn super::local_lifecycle::NativeLocalLifecycle>,
        queue_capacity: usize,
        authenticator: Box<dyn AuthorityProjectionQueryAuthenticator>,
        reconcile_interval: Duration,
    ) -> Result<Self, AgentProductionOwnerError> {
        if lifecycle
            .node()
            .map_err(AgentProductionOwnerError::Lifecycle)?
            != node
        {
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        }
        let system = lifecycle.system_attachment(queue_capacity)?;
        Self::start_with_lifecycle(
            node,
            limits,
            system,
            authenticator,
            reconcile_interval,
            Some((lifecycle, queue_capacity)),
        )
    }

    fn start_with_lifecycle(
        node: NodeId,
        limits: AgentSupervisorLimits,
        system_attachment: AgentRouteHostAttachment,
        authenticator: Box<dyn AuthorityProjectionQueryAuthenticator>,
        reconcile_interval: Duration,
        lifecycle: Option<(Box<dyn super::local_lifecycle::NativeLocalLifecycle>, usize)>,
    ) -> Result<Self, AgentProductionOwnerError> {
        if node == NodeId::ZERO || reconcile_interval.is_zero() {
            system_attachment.retire()?;
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        }
        let system_handle = system_attachment.handle();
        let target = match system_handle.authority_target() {
            Ok(target) if target.is_valid() => target,
            _ => {
                system_attachment.retire()?;
                return Err(AgentProductionOwnerError::InvalidConfiguration);
            }
        };
        let supervisor = match AgentSupervisorOwner::start(limits) {
            Ok(supervisor) => supervisor,
            Err(error) => {
                system_attachment.retire()?;
                return Err(error.into());
            }
        };
        let source = CleanAuthorityProjectionClient::new(
            Box::new(SystemAgentProjectionTransport {
                target,
                handle: system_handle,
            }),
            authenticator,
        );
        let mut owner = Self {
            node,
            system_agent: target.system_agent,
            supervisor: Some(supervisor),
            system: OwnedRouteSlot::Pending(system_attachment),
            local: OwnedRouteSlot::Empty,
            local_by_agent: None,
            shared: OwnedRouteSlot::Empty,
            shared_by_agent: None,
            source: Box::new(source),
            accepted_head: None,
            routes_verified: false,
            routes_need_quarantine: false,
            completed_local_publication: None,
            completed_local_install: None,
            reconcile_interval,
            reconcile_after: Instant::now(),
            lifecycle,
        };
        if let Some((lifecycle, capacity)) = &owner.lifecycle {
            ensure_local_slots(
                lifecycle.as_ref(),
                *capacity,
                &mut owner.local,
                &mut owner.local_by_agent,
            )?;
        }
        // Restored native admission, validated read contention or temporary
        // leader access may defer first publication. Retain quorum backends;
        // the caller exposes recovery control only.
        match owner.drive_if_due(Instant::now()) {
            Err(
                AgentProductionOwnerError::ProjectionBusy
                | AgentProductionOwnerError::ProjectionNotReady,
            ) => owner.quarantine_routes()?,
            Err(error) => {
                let _ = owner.shutdown_and_join();
                return Err(error);
            }
            // Initial NotReady is scheduled as Ok(false), but may still require
            // revoking a partially published route before the owner is returned.
            Ok(_) => owner.quarantine_routes()?,
        }
        Ok(owner)
    }

    pub(crate) fn handle(&self) -> AgentSupervisorHandle {
        self.supervisor
            .as_ref()
            .expect("production owner retains supervisor until consumed")
            .handle()
    }

    /// Continuations use the retained controller even while its native recovery
    /// obligations defer route publication. The controller authenticates the
    /// exact retained locator and phase; this grants no public ingress or route.
    fn retained_shared_lifecycle(
        &mut self,
    ) -> Result<&mut dyn super::local_lifecycle::NativeLocalLifecycle, AgentProductionOwnerError>
    {
        if !self.is_running() {
            return Err(AgentProductionOwnerError::ShutdownRequested);
        }
        match &mut self.lifecycle {
            Some((lifecycle, _)) => Ok(lifecycle.as_mut()),
            None => Err(AgentProductionOwnerError::InvalidConfiguration),
        }
    }

    /// Reserve a fresh signed Shared Create without executing or publishing it.
    /// The runtime selection is admitted and remains immutable across retries.
    pub(crate) fn reserve_shared_create(
        &mut self,
        descriptor: &super::sdk::AgentDescriptor,
        call: &super::sdk::authority::AuthorityCredentialCall,
        runtime: &super::clean_bootstrap::SharedGenesisRuntimePackage,
        replicas: &super::genesis::AgentReplicaCommittee,
    ) -> Result<super::genesis::AgentGenesisLocator, AgentProductionOwnerError> {
        if !self.is_ready() {
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        }
        self.retained_shared_lifecycle()?
            .reserve_shared_create(descriptor, call, runtime, replicas)
            .map_err(AgentProductionOwnerError::Lifecycle)
    }

    pub(crate) fn prepare_shared_create(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
    ) -> Result<super::clean_bootstrap::PreparedSharedGenesisEndorsement, AgentProductionOwnerError>
    {
        self.retained_shared_lifecycle()?
            .prepare_shared_create(locator)
            .map_err(AgentProductionOwnerError::Lifecycle)
    }

    /// A recovery-only ingress item or a request queued before quarantine can
    /// finish its exact already-owned management parent. Neither may allocate
    /// fresh custody while quarantined or restore routes. The ingress restriction
    /// remains binding even if readiness returns before worker dispatch.
    fn shared_create_locator(
        &mut self,
        descriptor: &super::sdk::AgentDescriptor,
        call: &super::sdk::authority::AuthorityCredentialCall,
        runtime: &super::clean_bootstrap::SharedGenesisRuntimePackage,
        replicas: &super::genesis::AgentReplicaCommittee,
        retained_only: bool,
    ) -> Result<super::genesis::AgentGenesisLocator, AgentProductionOwnerError> {
        if !retained_only && self.is_ready() {
            return self.reserve_shared_create(descriptor, call, runtime, replicas);
        }
        self.retained_shared_lifecycle()?
            .retained_shared_create_locator(descriptor, call, runtime, replicas)
            .map_err(AgentProductionOwnerError::Lifecycle)?
            .ok_or(AgentProductionOwnerError::ProjectionNotReady)
    }

    /// Endorse a sealed retained candidate; no route or quorum readiness is
    /// inferred from the configured signer's returned signature bytes.
    pub(crate) fn endorse_shared_create(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
    ) -> Result<Vec<super::committee::AuthoritySignature>, AgentProductionOwnerError> {
        self.retained_shared_lifecycle()?
            .endorse_shared_create(locator)
            .map_err(AgentProductionOwnerError::Lifecycle)
    }

    pub(crate) fn publish_shared_create(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
        signatures: Vec<super::committee::AuthoritySignature>,
    ) -> Result<super::genesis::AgentGenesisArchiveRecord, AgentProductionOwnerError> {
        self.retained_shared_lifecycle()?
            .publish_shared_create(locator, signatures)
            .map_err(AgentProductionOwnerError::Lifecycle)
    }

    /// Finish application, Authority finalization and terminal retention release
    /// before remote members obtain fresh admission evidence. The original ACK
    /// alone is not three-replica readiness: public publication follows elsewhere.
    pub(crate) fn complete_shared_create(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
    ) -> Result<super::sdk::authority::ManagementApplicationAck, AgentProductionOwnerError> {
        self.retained_shared_lifecycle()?
            .complete_shared_create(locator)
            .map_err(AgentProductionOwnerError::Lifecycle)
    }

    pub(crate) fn initialize_shared_management(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
    ) -> Result<(), AgentProductionOwnerError> {
        self.retained_shared_lifecycle()?
            .initialize_shared_management(locator)
            .map_err(AgentProductionOwnerError::Lifecycle)
    }

    pub(crate) fn prepare_shared_install(
        &mut self,
        install: super::sdk::InstallActor,
        call: super::sdk::authority::AuthorityCredentialCall,
        package: &super::package_admission::AdmittedActorPackage,
    ) -> Result<(), AgentProductionOwnerError> {
        if !self.is_ready() {
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        }
        self.retained_shared_lifecycle()?
            .prepare_shared_install(install, call, package)
            .map_err(AgentProductionOwnerError::Lifecycle)
    }

    /// Quarantine permits only the original retained Install. Keep this
    /// restriction even if readiness returns after recovery-only enqueue.
    /// A lookup cannot initialize management, allocate an intent or publish
    /// routes; normal completion still verifies durable custody.
    fn shared_install_locator(
        &mut self,
        install: &super::sdk::InstallActor,
        call: &super::sdk::authority::AuthorityCredentialCall,
        package: &super::package_admission::AdmittedActorPackage,
        retained_only: bool,
    ) -> Result<super::genesis::AgentGenesisLocator, AgentProductionOwnerError> {
        let locator = super::genesis::AgentGenesisLocator {
            space: crate::service::SpaceId(call.managed.space.0),
            agent: crate::service::AgentId(call.managed.agent.0),
        };
        if !retained_only && self.is_ready() {
            self.initialize_shared_management(locator)?;
            self.prepare_shared_install(install.clone(), call.clone(), package)?;
            return Ok(locator);
        }
        let retained = self
            .retained_shared_lifecycle()?
            .retained_shared_install_locator(install, call, package)
            .map_err(AgentProductionOwnerError::Lifecycle)?
            .ok_or(AgentProductionOwnerError::ProjectionNotReady)?;
        if retained != locator {
            return Err(AgentProductionOwnerError::InvalidProjection);
        }
        Ok(retained)
    }

    pub(crate) fn complete_shared_install(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
    ) -> Result<super::clean_authority_issuer::SignedManagementTerminal, AgentProductionOwnerError>
    {
        self.retained_shared_lifecycle()?
            .complete_shared_install(locator)
            .map_err(AgentProductionOwnerError::Lifecycle)
    }

    pub(crate) fn shared_install_denial(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
        install: &super::sdk::InstallActor,
        call: &super::sdk::authority::AuthorityCredentialCall,
    ) -> Result<Option<super::local_lifecycle::SharedInstallDenial>, AgentProductionOwnerError>
    {
        self.retained_shared_lifecycle()?
            .shared_install_denial(locator, install, call)
            .map_err(AgentProductionOwnerError::Lifecycle)
    }

    fn shared_create_denial(
        &mut self,
        locator: super::genesis::AgentGenesisLocator,
        descriptor: &super::sdk::AgentDescriptor,
        call: &super::sdk::authority::AuthorityCredentialCall,
    ) -> Result<Option<super::local_lifecycle::SharedCreateDenial>, AgentProductionOwnerError> {
        self.retained_shared_lifecycle()?
            .shared_create_denial(locator, descriptor, call)
            .map_err(AgentProductionOwnerError::Lifecycle)
    }

    /// Finish the coordinator's durable application before handing public
    /// archive data to members. This result deliberately makes no quorum or
    /// public-route readiness claim. Exact retries reuse the retained archive,
    /// then still perform native completion/fresh finality verification.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn create_shared_disposition(
        &mut self,
        submission: super::local_lifecycle::SharedCreateSubmission,
        retained_only: bool,
    ) -> super::local_lifecycle::SharedCreateResult {
        let runtime = super::clean_bootstrap::SharedGenesisRuntimePackage::External(
            submission.runtime().clone(),
        );
        let locator = self.shared_create_locator(
            submission.descriptor(),
            submission.call(),
            &runtime,
            submission.committee(),
            retained_only,
        )?;
        let archive = match self
            .retained_shared_lifecycle()?
            .shared_create_archive(locator)
            .map_err(AgentProductionOwnerError::Lifecycle)?
        {
            Some(record) => {
                // OGAR is durable before Authority publication: its mere
                // presence is not proof that Invoke/ACK finished. Replay the
                // existing publisher with the exact retained QC, never obtain
                // a replacement endorsement. Retired entries refuse publish;
                // only normal native completion below may prove that terminal.
                let signatures = record
                    .provision()
                    .evidence()
                    .certificate()
                    .signatures()
                    .to_vec();
                match self.publish_shared_create(locator, signatures) {
                    Ok(published) => published,
                    Err(AgentProductionOwnerError::Lifecycle(
                        super::shared_host::SharedAgentHostError::Conflict,
                    )) => record,
                    Err(error) => return Err(error),
                }
            }
            None => {
                let signatures = match self.endorse_shared_create(locator) {
                    Ok(signatures) => signatures,
                    Err(
                        error @ AgentProductionOwnerError::Lifecycle(
                            super::shared_host::SharedAgentHostError::ScopeMismatch,
                        ),
                    ) => {
                        // Only the normal native preparation/denial
                        // continuation can return this terminal. CND1 may
                        // precede custody release, so Unavailable/Conflict
                        // never become a denial merely because it is present.
                        return match self.shared_create_denial(
                            locator,
                            submission.descriptor(),
                            submission.call(),
                        )? {
                            Some(denial) => Ok(
                                super::local_lifecycle::SharedCreateDisposition::Denied(denial),
                            ),
                            None => Err(error),
                        };
                    }
                    Err(error) => return Err(error),
                };
                self.publish_shared_create(locator, signatures)?
            }
        };
        let acknowledgement = self.complete_shared_create(locator)?;
        submission
            .applied(acknowledgement, archive)
            .map_err(|_| AgentProductionOwnerError::InvalidProjection)
    }

    /// Exact signed Install through the same native continuation and route
    /// reconciliation as recovered work. Only an actual retained certificate
    /// may turn policy refusal into a terminal denial.
    #[cfg(feature = "experimental-state-blocks")]
    pub(crate) fn install_shared_disposition(
        &mut self,
        submission: super::local_lifecycle::SharedInstallSubmission,
        retained_only: bool,
    ) -> super::local_lifecycle::SharedInstallResult {
        use super::local_lifecycle::SharedInstallDisposition;
        let install = submission.install().clone();
        let call = submission.call().clone();
        let locator = super::genesis::AgentGenesisLocator {
            space: crate::service::SpaceId(call.managed.space.0),
            agent: crate::service::AgentId(call.managed.agent.0),
        };
        let result = (|| {
            self.shared_install_locator(&install, &call, submission.package(), retained_only)?;
            self.complete_shared_install(locator)
        })();
        let disposition = match result {
            Ok(super::clean_authority_issuer::SignedManagementTerminal::Applied(ack)) => {
                SharedInstallDisposition::Applied(ack)
            }
            Ok(super::clean_authority_issuer::SignedManagementTerminal::Rejected(failure)) => {
                SharedInstallDisposition::Failed(failure)
            }
            Err(
                error @ AgentProductionOwnerError::Lifecycle(
                    super::shared_host::SharedAgentHostError::ScopeMismatch,
                ),
            ) => match self.shared_install_denial(locator, &install, &call)? {
                Some(denial) => return Ok(SharedInstallDisposition::Denied(denial)),
                None => return Err(error),
            },
            Err(error) => return Err(error),
        };
        submission
            .encode_response(&disposition)
            .map_err(|_| AgentProductionOwnerError::InvalidProjection)?;
        // The native result was finalized and retired. Reconcile actual
        // installed actor state before replying; do not infer a route from ACK.
        self.reconcile()?;
        Ok(disposition)
    }

    /// Fresh native finality, durable member publication and actual local
    /// transport attachment. This acknowledges neither a management operation
    /// nor cluster readiness. A new Agent may have no callable actor routes.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn admit_shared_member(
        &mut self,
        submission: super::local_lifecycle::SharedMemberAdmissionSubmission,
    ) -> super::local_lifecycle::SharedMemberAdmissionResult {
        // Client routing scope must match this independently admitted owner,
        // before fresh reads, archive preparation or any native storage work.
        if submission.expected_node() != self.node {
            return Err(AgentProductionOwnerError::Lifecycle(
                super::shared_host::SharedAgentHostError::ScopeMismatch,
            ));
        }
        if !self.is_ready() {
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        }
        let record = submission.record();
        let locator = submission.locator();
        let expected = record
            .provision()
            .proposal()
            .clean_descriptor()
            .map_err(|_| AgentProductionOwnerError::InvalidProjection)?;
        self.retained_shared_lifecycle()?
            .admit_member_archive(record)
            .map_err(AgentProductionOwnerError::Lifecycle)?;
        self.reconcile()?;
        let generation = self
            .shared_by_agent
            .as_ref()
            .and_then(|slots| slots.get(&AgentId(locator.agent.0)))
            .filter(|generation| !generation.slot.is_empty())
            .ok_or(AgentProductionOwnerError::Lifecycle(
                super::shared_host::SharedAgentHostError::Unavailable,
            ))?;
        // Reconciliation retains a real Pending attachment for a generation
        // with no actors. Require the live transport/fingerprint and exact
        // descriptor, not Published actor routes or a quorum claim.
        let physical = generation
            .generation
            .projection()
            .map_err(AgentProductionOwnerError::Lifecycle)?;
        if &physical.descriptor != expected {
            return Err(AgentProductionOwnerError::InvalidProjection);
        }
        Ok(locator)
    }

    pub(crate) fn create_local_disposition(
        &mut self,
        descriptor: super::sdk::AgentDescriptor,
        call: super::sdk::authority::AuthorityCredentialCall,
        runtime: super::package_admission::AdmittedRuntimePackage,
    ) -> super::local_lifecycle::LocalCreateResult {
        use super::local_lifecycle::{LocalCreateDisposition, LocalCreateSubmission};
        let submission =
            LocalCreateSubmission::new(descriptor.clone(), call.clone(), runtime.clone())
                .map_err(|_| AgentProductionOwnerError::Authentication)?;
        match self.create_local_agent(descriptor, call, runtime) {
            Ok((agent, ack)) => Ok(LocalCreateDisposition::Created(agent, ack)),
            Err(
                error @ AgentProductionOwnerError::Lifecycle(
                    super::shared_host::SharedAgentHostError::ScopeMismatch,
                ),
            ) => {
                let (lifecycle, _) = self
                    .lifecycle
                    .as_mut()
                    .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
                match lifecycle
                    .retained_denial(&submission)
                    .map_err(AgentProductionOwnerError::Lifecycle)?
                {
                    Some(denial) => Ok(LocalCreateDisposition::Denied(denial)),
                    None => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn create_local_agent(
        &mut self,
        descriptor: super::sdk::AgentDescriptor,
        call: super::sdk::authority::AuthorityCredentialCall,
        runtime: super::package_admission::AdmittedRuntimePackage,
    ) -> Result<(AgentId, super::sdk::authority::ManagementApplicationAck), AgentProductionOwnerError>
    {
        if !self.is_ready() {
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        }
        // Every attempt still authenticates and reopens physical application
        // evidence through the lifecycle. Errors invalidate prior delivery
        // deduplication instead of leaving a stale success available.
        let previous = self.completed_local_publication.take();
        self.completed_local_install = None;
        let started = Instant::now();
        tracing::debug!(agent = ?descriptor.identity.agent, "Local Create lifecycle started");
        let had_local_attachment =
            self.local_by_agent
                .as_ref()
                .map_or(!self.local.is_empty(), |slots| {
                    slots
                        .get(&descriptor.identity.agent)
                        .is_some_and(|slot| !slot.is_empty())
                });
        let (lifecycle, capacity) = self
            .lifecycle
            .as_mut()
            .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
        let result = lifecycle
            .create(descriptor, call, runtime)
            .map_err(AgentProductionOwnerError::Lifecycle)?;
        tracing::debug!(agent = ?result.0, elapsed_ms = started.elapsed().as_millis() as u64, "Local Create lifecycle complete");
        ensure_local_slots(
            lifecycle.as_ref(),
            *capacity,
            &mut self.local,
            &mut self.local_by_agent,
        )?;
        self.finish_local_create_publication(result, previous, had_local_attachment, started)
    }

    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn create_external_local_disposition(
        &mut self,
        submission: super::local_lifecycle::LocalStateCreateSubmission,
    ) -> super::local_lifecycle::LocalCreateResult {
        use super::local_lifecycle::LocalCreateDisposition;
        let retained = submission.clone();
        match self.create_external_local_agent(submission) {
            Ok((agent, ack)) => Ok(LocalCreateDisposition::Created(agent, ack)),
            Err(
                error @ AgentProductionOwnerError::Lifecycle(
                    super::shared_host::SharedAgentHostError::ScopeMismatch,
                ),
            ) => {
                let (lifecycle, _) = self
                    .lifecycle
                    .as_mut()
                    .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
                match lifecycle
                    .retained_state_denial(&retained)
                    .map_err(AgentProductionOwnerError::Lifecycle)?
                {
                    Some(denial) => Ok(LocalCreateDisposition::Denied(denial)),
                    None => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    fn create_external_local_agent(
        &mut self,
        submission: super::local_lifecycle::LocalStateCreateSubmission,
    ) -> Result<(AgentId, super::sdk::authority::ManagementApplicationAck), AgentProductionOwnerError>
    {
        if !self.is_ready() {
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        }
        let agent = submission.descriptor().identity.agent;
        let previous = self.completed_local_publication.take();
        self.completed_local_install = None;
        let started = Instant::now();
        tracing::debug!(agent = ?agent, "external Local Create lifecycle started");
        let had_local_attachment = self
            .local_by_agent
            .as_ref()
            .map_or(!self.local.is_empty(), |slots| {
                slots.get(&agent).is_some_and(|slot| !slot.is_empty())
            });
        let (lifecycle, capacity) = self
            .lifecycle
            .as_mut()
            .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
        let result = lifecycle
            .create_external(submission)
            .map_err(AgentProductionOwnerError::Lifecycle)?;
        tracing::debug!(agent = ?agent, elapsed_ms = started.elapsed().as_millis() as u64, "external Local Create lifecycle complete");
        ensure_local_slots(
            lifecycle.as_ref(),
            *capacity,
            &mut self.local,
            &mut self.local_by_agent,
        )?;
        tracing::debug!(agent = ?agent, elapsed_ms = started.elapsed().as_millis() as u64, "external Local Create slots refreshed");
        self.finish_local_create_publication(result, previous, had_local_attachment, started)
    }

    fn finish_local_create_publication(
        &mut self,
        result: (AgentId, super::sdk::authority::ManagementApplicationAck),
        previous: Option<(super::sdk::Hash, AuthorityProjectionHead)>,
        had_local_attachment: bool,
        started: Instant,
    ) -> Result<(AgentId, super::sdk::authority::ManagementApplicationAck), AgentProductionOwnerError>
    {
        let acknowledgement = result.1.commitment();
        if completed_local_publication_matches(
            previous,
            acknowledgement,
            self.accepted_head,
            had_local_attachment,
        ) {
            self.completed_local_publication = previous;
            tracing::debug!(agent = ?result.0, elapsed_ms = started.elapsed().as_millis() as u64, "Local Create exact publication reused");
            return Ok(result);
        }
        // The controller released both host locks before route reconciliation.
        // Errors leave durable application evidence for an exact retry.
        self.reconcile()?;
        self.completed_local_publication = self.accepted_head.map(|head| (acknowledgement, head));
        tracing::debug!(agent = ?result.0, elapsed_ms = started.elapsed().as_millis() as u64, "Local Create publication complete");
        Ok(result)
    }

    /// Native Install completion requires verified Authority/physical route
    /// publication. Exact retries may reuse an unchanged verified publication,
    /// but must still reopen lifecycle evidence and check the active route.
    pub(crate) fn install_local_actor(
        &mut self,
        install: super::sdk::InstallActor,
        call: super::sdk::authority::AuthorityCredentialCall,
        package: super::package_admission::AdmittedActorPackage,
    ) -> Result<super::sdk::authority::ManagementApplicationAck, AgentProductionOwnerError> {
        if !self.is_ready() {
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        }
        self.completed_local_publication = None;
        let previous = self.completed_local_install.take();
        let had_local_attachment =
            self.local_by_agent
                .as_ref()
                .map_or(!self.local.is_empty(), |slots| {
                    slots
                        .get(&call.managed.agent)
                        .is_some_and(|slot| !slot.is_empty())
                });
        let key = AgentRouteKey::new(call.managed.space, call.managed.agent, install.entry.actor)?;
        let runtime = call.managed.runtime_deployment;
        let deployment = install.entry.deployment;
        let program = install.entry.program;
        let (lifecycle, capacity) = self
            .lifecycle
            .as_mut()
            .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
        let acknowledgement = lifecycle
            .install(install, call, package)
            .map_err(AgentProductionOwnerError::Lifecycle)?;
        ensure_local_slots(
            lifecycle.as_ref(),
            *capacity,
            &mut self.local,
            &mut self.local_by_agent,
        )?;
        let current_identity = self
            .supervisor
            .as_ref()
            .and_then(|supervisor| supervisor.handle().snapshot(key).ok())
            .map(|snapshot| snapshot.identity());
        if installed_local_route_matches(current_identity, key, runtime, deployment, program)
            && completed_local_install_matches(
                previous,
                acknowledgement.commitment(),
                self.accepted_head,
                had_local_attachment,
                current_identity,
            )
        {
            self.completed_local_install = previous;
            tracing::debug!(?key, "Local Install exact publication reused");
            return Ok(acknowledgement);
        }
        self.reconcile()?;
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
        let identity = supervisor.handle().snapshot(key)?.identity();
        if !installed_local_route_matches(Some(identity), key, runtime, deployment, program) {
            return Err(AgentProductionOwnerError::InvalidProjection);
        }
        self.completed_local_install = self
            .accepted_head
            .map(|head| (acknowledgement.commitment(), head, identity));
        Ok(acknowledgement)
    }

    pub(crate) fn is_running(&self) -> bool {
        self.supervisor
            .as_ref()
            .is_some_and(|supervisor| supervisor.handle().is_running())
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.is_running() && self.routes_verified && self.accepted_head.is_some()
    }

    pub(crate) fn prepare_admin(
        &mut self,
        draft: &super::sdk::authority::AuthorityAdminCall,
    ) -> super::local_lifecycle::AuthorityAdminPreparationResult {
        if !self.is_ready() {
            return Err(super::shared_host::SharedAgentHostError::Unavailable);
        }
        self.lifecycle
            .as_mut()
            .ok_or(super::shared_host::SharedAgentHostError::Unavailable)?
            .0
            .prepare_admin(draft)
    }

    pub(crate) fn submit_admin(
        &mut self,
        call: &super::sdk::authority::AuthorityAdminCall,
        preparation: &super::clean_bootstrap::NativeAuthorityAdminPreparation,
    ) -> super::local_lifecycle::AuthorityAdminSubmissionResult {
        if !self.is_running() {
            return Err(super::shared_host::SharedAgentHostError::Unavailable);
        }
        if !self.is_ready()
            && !self
                .lifecycle
                .as_mut()
                .ok_or(super::shared_host::SharedAgentHostError::Unavailable)?
                .0
                .retains_admin(call, preparation)?
        {
            return Err(super::shared_host::SharedAgentHostError::ScopeMismatch);
        }
        self.lifecycle
            .as_mut()
            .ok_or(super::shared_host::SharedAgentHostError::Unavailable)?
            .0
            .submit_admin(call, preparation)
    }

    pub(crate) fn prepare_operation(
        &mut self,
        call: &super::sdk::authority_operation::AuthorityOperationCall,
    ) -> super::local_lifecycle::AuthorityOperationPreparationResult {
        if !self.is_running() {
            return Err(super::shared_host::SharedAgentHostError::Unavailable);
        }
        if !self.is_ready()
            && !self
                .lifecycle
                .as_mut()
                .ok_or(super::shared_host::SharedAgentHostError::Unavailable)?
                .0
                .retains_operation(call, None)?
        {
            return Err(super::shared_host::SharedAgentHostError::ScopeMismatch);
        }
        self.lifecycle
            .as_mut()
            .ok_or(super::shared_host::SharedAgentHostError::Unavailable)?
            .0
            .prepare_operation(call)
    }

    pub(crate) fn authorize_operation(
        &mut self,
        call: &super::sdk::authority_operation::AuthorityOperationCall,
        context: super::sdk::InvocationContext,
        issued_at: u64,
    ) -> Result<
        super::clean_bootstrap::NativeAuthorityOperationDecision,
        super::shared_host::SharedAgentHostError,
    > {
        if !self.is_running() {
            return Err(super::shared_host::SharedAgentHostError::Unavailable);
        }
        if !self.is_ready()
            && !self
                .lifecycle
                .as_mut()
                .ok_or(super::shared_host::SharedAgentHostError::Unavailable)?
                .0
                .retains_operation(call, Some(&context))?
        {
            return Err(super::shared_host::SharedAgentHostError::ScopeMismatch);
        }
        self.lifecycle
            .as_mut()
            .ok_or(super::shared_host::SharedAgentHostError::Unavailable)?
            .0
            .authorize_operation(call, context, issued_at)
    }

    pub(crate) fn install_local_host(
        &mut self,
        attachment: AgentRouteHostAttachment,
    ) -> Result<(), AgentProductionOwnerError> {
        if self.local_by_agent.is_some() {
            attachment.retire()?;
            return Err(AgentProductionOwnerError::DuplicateHost);
        }
        install_pending(&mut self.local, attachment)
    }

    pub(crate) fn install_shared_host(
        &mut self,
        attachment: AgentRouteHostAttachment,
    ) -> Result<(), AgentProductionOwnerError> {
        if self.shared_by_agent.is_some() {
            attachment.retire()?;
            return Err(AgentProductionOwnerError::DuplicateHost);
        }
        install_pending(&mut self.shared, attachment)
    }

    pub(crate) fn set_shutdown_signal(&mut self, shutdown: Arc<AtomicBool>) {
        self.source.set_shutdown_signal(shutdown);
    }

    pub(crate) fn drive_if_due(&mut self, now: Instant) -> Result<bool, AgentProductionOwnerError> {
        if now < self.reconcile_after {
            return Ok(false);
        }
        if let Some((lifecycle, _)) = &self.lifecycle {
            if lifecycle
                .management_admission_held()
                .map_err(AgentProductionOwnerError::Lifecycle)?
            {
                // Preparation/issuance spans multiple client exchanges. Do not
                // turn its intentional exclusion into a fatal projection error.
                // Keep the deadline overdue so release triggers a fresh refresh.
                return Ok(false);
            }
        }
        match self.reconcile_at(now) {
            // No ingress has been published yet. Retain the quorum participant
            // while election or leader access is unavailable; tearing it down
            // here can prevent every other node from becoming ready as well.
            Err(AgentProductionOwnerError::ProjectionNotReady) if self.accepted_head.is_none() => {
                self.reconcile_after = Instant::now()
                    .max(now)
                    .checked_add(INITIAL_RECONCILIATION_RETRY)
                    .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
                Ok(false)
            }
            result => result.map(|()| true),
        }
    }

    /// Reconciliation is crate-private: only the node owner may mutate route
    /// publication after construction.
    pub(crate) fn reconcile(&mut self) -> Result<(), AgentProductionOwnerError> {
        self.reconcile_at(Instant::now())
    }

    fn reconcile_at(&mut self, now: Instant) -> Result<(), AgentProductionOwnerError> {
        if self.routes_need_quarantine {
            // Ingress must be hidden before any draining route refresh. The
            // worker completes that boundary before another inventory attempt.
            return Err(AgentProductionOwnerError::ProjectionBusy);
        }
        let result = self.reconcile_inventory_at(now);
        if matches!(
            result,
            Err(AgentProductionOwnerError::ProjectionBusy
                | AgentProductionOwnerError::ProjectionNotReady)
        ) {
            self.routes_verified = false;
            self.routes_need_quarantine = true;
            self.reconcile_after = Instant::now()
                .max(now)
                .checked_add(INITIAL_RECONCILIATION_RETRY)
                .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
        }
        result
    }

    pub(crate) fn needs_route_quarantine(&self) -> bool {
        self.routes_need_quarantine
    }

    /// The worker must hide ingress before calling this potentially draining
    /// operation. Empty identities revoke publication without retiring the
    /// physical backends or their quorum participants.
    pub(crate) fn quarantine_routes(&mut self) -> Result<(), AgentProductionOwnerError> {
        if !self.routes_need_quarantine {
            return Ok(());
        }
        let supervisor = self
            .supervisor
            .as_mut()
            .ok_or(AgentProductionOwnerError::Supervisor(
                AgentSupervisorError::Closed,
            ))?;
        for slot in [&mut self.system, &mut self.local, &mut self.shared]
            .into_iter()
            .chain(
                self.local_by_agent
                    .iter_mut()
                    .flat_map(|slots| slots.values_mut()),
            )
            .chain(
                self.shared_by_agent
                    .iter_mut()
                    .flat_map(|slots| slots.values_mut().map(|entry| &mut entry.slot)),
            )
        {
            if let OwnedRouteSlot::Published { publication, .. } = slot {
                if !publication.snapshots().is_empty() {
                    *publication = supervisor.refresh(publication, Vec::new())?;
                }
            }
        }
        self.routes_need_quarantine = false;
        Ok(())
    }

    fn reconcile_inventory_at(&mut self, now: Instant) -> Result<(), AgentProductionOwnerError> {
        let started = Instant::now();
        tracing::debug!("Authority inventory reconciliation started");
        // A new attempt can change or retire attachments even if it fails.
        // Only a subsequent successful lifecycle publication may remember a
        // response again; reopening always starts without this optimization.
        self.completed_local_publication = None;
        self.completed_local_install = None;
        let inventory = self.source.load_inventory()?;
        tracing::debug!(
            agents = inventory.agents.len(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "Authority inventory loaded; reconciling routes"
        );
        accept_head(self.accepted_head, inventory.head)?;
        #[cfg(test)]
        if std::env::var_os("VOS_TEST_INNER_DIAGNOSTICS").is_some() {
            for projection in &inventory.agents {
                eprintln!(
                    "inventory system={} profile={:?} local_replica={} actors={} roots={}",
                    projection.descriptor().identity.agent == self.system_agent,
                    projection.descriptor().identity.profile,
                    projection
                        .descriptor()
                        .replicas
                        .iter()
                        .any(|replica| replica.node == self.node),
                    projection.actors().len(),
                    projection
                        .actors()
                        .iter()
                        .filter(|actor| actor.root_provenance)
                        .count()
                );
            }
        }
        validate_root_provenance(&inventory, self.system_agent)?;
        // This lifecycle boundary audits the complete namespace. Serving
        // requests only validate the root lease and their pinned Agent slot.
        if self.local_by_agent.is_some() {
            if let Some((lifecycle, capacity)) = &self.lifecycle {
                ensure_local_slots(
                    lifecycle.as_ref(),
                    *capacity,
                    &mut self.local,
                    &mut self.local_by_agent,
                )?;
            }
        }
        let _authenticated_principal = inventory.principal;
        let mut system = Vec::new();
        let mut local = Vec::new();
        let mut shared = Vec::new();
        for projection in inventory.agents {
            let descriptor = projection.descriptor();
            let is_local_replica = descriptor
                .replicas
                .iter()
                .any(|replica| replica.node == self.node);
            if descriptor.identity.agent == self.system_agent {
                if descriptor.identity.profile != AgentProfile::Shared || !is_local_replica {
                    self.request_shutdown();
                    return Err(AgentProductionOwnerError::InvalidSystemAgent);
                }
                system.push(projection);
                continue;
            }
            match descriptor.identity.profile {
                AgentProfile::Local
                    if descriptor.replicas.len() == 1
                        && descriptor.replicas[0].node == self.node =>
                {
                    local.push(projection);
                }
                AgentProfile::Shared if is_local_replica => shared.push(projection),
                AgentProfile::Private | AgentProfile::Local | AgentProfile::Shared => {}
            }
        }
        if system.len() != 1 {
            self.request_shutdown();
            return Err(AgentProductionOwnerError::MissingSystemAgent);
        }

        if let Some((lifecycle, _)) = &self.lifecycle {
            match lifecycle
                .shared_generations()
                .map_err(AgentProductionOwnerError::Lifecycle)?
            {
                Some(generations) if self.shared.is_empty() => {
                    // A newly finalized Create can precede this member's
                    // archive admission and transport attachment. That is not
                    // permission to forget a generation already owned here:
                    // check its presence before refresh removes stale slots.
                    validate_known_shared_presence(
                        self.shared_by_agent
                            .iter()
                            .flat_map(|slots| slots.keys().copied()),
                        generations.iter().map(|generation| generation.agent()),
                        &shared,
                    )?;
                    let supervisor =
                        self.supervisor
                            .as_mut()
                            .ok_or(AgentProductionOwnerError::Supervisor(
                                AgentSupervisorError::Closed,
                            ))?;
                    ensure_shared_generations(
                        supervisor,
                        self.system_agent,
                        &mut self.shared_by_agent,
                        generations,
                    )?;
                }
                None if self.shared_by_agent.is_none() => {}
                _ => return Err(AgentProductionOwnerError::InvalidConfiguration),
            }
        }

        let supervisor = self
            .supervisor
            .as_mut()
            .ok_or(AgentProductionOwnerError::Supervisor(
                AgentSupervisorError::Closed,
            ))?;
        if let Err(error) = reconcile_slot(supervisor, &mut self.system, inventory.head, system) {
            self.request_shutdown();
            return Err(error);
        }
        if let Some(slots) = &mut self.local_by_agent {
            let mut projected: BTreeMap<_, _> = local
                .into_iter()
                .map(|projection| (projection.descriptor().identity.agent, projection))
                .collect();
            if projected.keys().any(|agent| !slots.contains_key(agent)) {
                return Err(AgentProductionOwnerError::InvalidProjection);
            }
            for (agent, slot) in slots {
                reconcile_slot(
                    supervisor,
                    slot,
                    inventory.head,
                    projected.remove(agent).into_iter().collect(),
                )?;
            }
        } else {
            reconcile_slot(supervisor, &mut self.local, inventory.head, local)?;
        }
        if let Some(slots) = &mut self.shared_by_agent {
            let mut projected: BTreeMap<_, _> = shared
                .into_iter()
                .map(|projection| (projection.descriptor().identity.agent, projection))
                .collect();
            if projected.iter().any(|(agent, projection)| {
                !slots.contains_key(agent) && !shared_handoff_projection_can_wait(projection)
            }) {
                return Err(AgentProductionOwnerError::InvalidProjection);
            }
            // Unknown supported members remain completely unexposed. A LIVE
            // Authority descriptor is not physical readiness: only the native
            // member admission path can supply a generation handle, which then
            // goes through the ordinary exact projection authorization below.
            for (agent, generation) in slots {
                reconcile_slot(
                    supervisor,
                    &mut generation.slot,
                    inventory.head,
                    projected.remove(agent).into_iter().collect(),
                )?;
            }
        } else {
            reconcile_slot(supervisor, &mut self.shared, inventory.head, shared)?;
        }
        self.accepted_head = Some(inventory.head);
        self.routes_verified = true;
        // Every successful reconciliation, including a lifecycle-triggered
        // publication, starts a full quiet interval after completion. Physical
        // inventory work may itself take longer than the configured interval.
        self.reconcile_after = Instant::now()
            .max(now)
            .checked_add(self.reconcile_interval)
            .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            "Authority route reconciliation complete"
        );
        Ok(())
    }

    pub(crate) fn request_shutdown(&self) {
        if let Some(supervisor) = self.supervisor.as_ref() {
            supervisor.request_shutdown();
        }
        for slot in [&self.system, &self.local, &self.shared]
            .into_iter()
            .chain(self.local_by_agent.iter().flat_map(|slots| slots.values()))
            .chain(
                self.shared_by_agent
                    .iter()
                    .flat_map(|slots| slots.values().map(|entry| &entry.slot)),
            )
        {
            if let OwnedRouteSlot::Pending(attachment) = slot {
                let _ = attachment.handle().request_retire();
            }
        }
    }

    pub(crate) fn shutdown_and_join(mut self) -> Result<(), AgentProductionOwnerError> {
        self.request_shutdown();
        let pending_result = self.retire_pending_routes();
        let supervisor = self
            .supervisor
            .take()
            .ok_or(AgentProductionOwnerError::Supervisor(
                AgentSupervisorError::Closed,
            ))?;
        let supervisor_result = supervisor.shutdown_and_join().map_err(Into::into);
        pending_result.and(supervisor_result)
    }

    fn retire_pending_routes(&mut self) -> Result<(), AgentProductionOwnerError> {
        let mut result = Ok(());
        for slot in [&mut self.system, &mut self.local, &mut self.shared]
            .into_iter()
            .chain(
                self.local_by_agent
                    .iter_mut()
                    .flat_map(|slots| slots.values_mut()),
            )
            .chain(
                self.shared_by_agent
                    .iter_mut()
                    .flat_map(|slots| slots.values_mut().map(|entry| &mut entry.slot)),
            )
        {
            if let Err(error) = retire_pending_slot(slot) {
                result = Err(error);
            }
        }
        result
    }
}

/// Atomically exposed with the supervisor after authenticated startup; holds
/// dispatch handles only, never ownership of the physical system host.
#[derive(Clone)]
pub(crate) struct CleanAgentIngress {
    pub(crate) node: NodeId,
    pub(crate) supervisor: AgentSupervisorHandle,
    pub(crate) authority: AgentRouteHostHandle,
}

impl Drop for AgentProductionOwner {
    fn drop(&mut self) {
        self.request_shutdown();
        let _ = self.retire_pending_routes();
        if let Some(supervisor) = self.supervisor.take() {
            let _ = supervisor.shutdown_and_join();
        }
    }
}

fn validate_root_provenance(
    inventory: &AgentAuthorityInventory,
    system_agent: AgentId,
) -> Result<(), AgentProductionOwnerError> {
    let mut roots = inventory
        .agents
        .iter()
        .flat_map(|projection| projection.actors())
        .filter(|actor| actor.root_provenance);
    let root = roots
        .next()
        .ok_or(AgentProductionOwnerError::InvalidSystemAgent)?;
    if root.agent != system_agent || roots.next().is_some() {
        return Err(AgentProductionOwnerError::InvalidSystemAgent);
    }
    Ok(())
}

fn retire_pending_slot(slot: &mut OwnedRouteSlot) -> Result<(), AgentProductionOwnerError> {
    match std::mem::replace(slot, OwnedRouteSlot::Empty) {
        OwnedRouteSlot::Pending(attachment) => attachment.retire().map_err(Into::into),
        published @ OwnedRouteSlot::Published { .. } => {
            *slot = published;
            Ok(())
        }
        OwnedRouteSlot::Empty => Ok(()),
    }
}

fn install_pending(
    slot: &mut OwnedRouteSlot,
    attachment: AgentRouteHostAttachment,
) -> Result<(), AgentProductionOwnerError> {
    if !slot.is_empty() {
        attachment.retire()?;
        return Err(AgentProductionOwnerError::DuplicateHost);
    }
    *slot = OwnedRouteSlot::Pending(attachment);
    Ok(())
}

fn ensure_local_slots(
    lifecycle: &dyn super::local_lifecycle::NativeLocalLifecycle,
    capacity: usize,
    legacy: &mut OwnedRouteSlot,
    by_agent: &mut Option<BTreeMap<AgentId, OwnedRouteSlot>>,
) -> Result<(), AgentProductionOwnerError> {
    match lifecycle.local_agents()? {
        None if by_agent.is_none() => {
            if legacy.is_empty() {
                *legacy = OwnedRouteSlot::Pending(lifecycle.local_attachment(capacity)?);
            }
        }
        Some(agents) if legacy.is_empty() => {
            if agents.len() > MAX_INVENTORY_AGENTS
                || agents.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(AgentProductionOwnerError::InvalidConfiguration);
            }
            let slots = by_agent.get_or_insert_with(BTreeMap::new);
            for agent in agents {
                let slot = slots.entry(agent).or_insert(OwnedRouteSlot::Empty);
                if slot.is_empty() {
                    *slot = OwnedRouteSlot::Pending(lifecycle.local_attachment_for_agent(agent)?);
                }
            }
        }
        _ => return Err(AgentProductionOwnerError::InvalidConfiguration),
    }
    Ok(())
}

fn retire_owned_slot(
    supervisor: &mut AgentSupervisorOwner,
    slot: &mut OwnedRouteSlot,
) -> Result<(), AgentProductionOwnerError> {
    match std::mem::replace(slot, OwnedRouteSlot::Empty) {
        OwnedRouteSlot::Empty => Ok(()),
        OwnedRouteSlot::Pending(attachment) => attachment.retire().map_err(Into::into),
        OwnedRouteSlot::Published {
            handle,
            publication,
        } => match supervisor.detach(&publication) {
            Ok(()) => Ok(()),
            Err(error) => {
                *slot = OwnedRouteSlot::Published {
                    handle,
                    publication,
                };
                supervisor.request_shutdown();
                Err(error.into())
            }
        },
    }
}

fn validate_known_shared_presence(
    mut known: impl Iterator<Item = AgentId>,
    current: impl Iterator<Item = AgentId>,
    projected: &[AgentAuthorityRouteProjection],
) -> Result<(), AgentProductionOwnerError> {
    let current: BTreeSet<_> = current.collect();
    let projected: BTreeSet<_> = projected
        .iter()
        .map(|projection| projection.descriptor().identity.agent)
        .collect();
    if known.any(|agent| projected.contains(&agent) && !current.contains(&agent)) {
        return Err(AgentProductionOwnerError::InvalidProjection);
    }
    Ok(())
}

fn shared_handoff_projection_can_wait(projection: &AgentAuthorityRouteProjection) -> bool {
    #[cfg(feature = "experimental-state-blocks")]
    {
        let descriptor = projection.descriptor();
        super::replay::external_shared_descriptor_supported(descriptor)
            && descriptor.runtime_contract.lifecycle_abi
                == super::sdk::state_execution::STATE_EXECUTION_ABI_ID
    }
    #[cfg(not(feature = "experimental-state-blocks"))]
    {
        let _ = projection;
        false
    }
}

fn ensure_shared_generations(
    supervisor: &mut AgentSupervisorOwner,
    system_agent: AgentId,
    by_agent: &mut Option<BTreeMap<AgentId, OwnedSharedGeneration>>,
    generations: Vec<crate::network::shared_agent::SharedAgentRouteHandle>,
) -> Result<(), AgentProductionOwnerError> {
    if generations.len() > super::shared_host::MAX_SHARED_HOST_AGENTS
        || generations.iter().any(|generation| {
            generation.agent() == system_agent || generation.agent() == AgentId::ZERO
        })
        || generations
            .windows(2)
            .any(|pair| pair[0].agent() >= pair[1].agent())
    {
        return Err(AgentProductionOwnerError::InvalidConfiguration);
    }
    let desired: BTreeMap<_, _> = generations
        .into_iter()
        .map(|generation| (generation.agent(), generation))
        .collect();
    let slots = by_agent.get_or_insert_with(BTreeMap::new);
    let retiring: Vec<_> = slots
        .iter()
        .filter_map(|(agent, existing)| {
            (existing.slot.is_empty()
                || desired
                    .get(agent)
                    .is_none_or(|current| !current.same_generation(&existing.generation)))
            .then_some(*agent)
        })
        .collect();
    // Unpublish and drain the previous exact attachment before installing a
    // replacement. A failed detach retains ownership for global shutdown.
    for agent in retiring {
        retire_owned_slot(supervisor, &mut slots.get_mut(&agent).unwrap().slot)?;
        slots.remove(&agent);
    }
    for (agent, generation) in desired {
        if !slots.contains_key(&agent) {
            let attachment =
                super::supervisor_adapters::shared_agent_supervisor_attachment_for_generation(
                    generation.clone(),
                )?;
            slots.insert(
                agent,
                OwnedSharedGeneration {
                    generation,
                    slot: OwnedRouteSlot::Pending(attachment),
                },
            );
        }
    }
    Ok(())
}

fn reconcile_slot(
    supervisor: &mut AgentSupervisorOwner,
    slot: &mut OwnedRouteSlot,
    head: AuthorityProjectionHead,
    projection: Vec<AgentAuthorityRouteProjection>,
) -> Result<(), AgentProductionOwnerError> {
    let projection_is_empty = projection.is_empty();
    match std::mem::replace(slot, OwnedRouteSlot::Empty) {
        OwnedRouteSlot::Empty => Ok(()),
        OwnedRouteSlot::Pending(attachment) => {
            let handle = attachment.handle();
            let identities = match handle.authorize_projection(head, projection) {
                Ok(identities) => match normalized_identities(&identities) {
                    Ok(identities) => identities,
                    Err(error) => return retire_pending_after_error(attachment, error),
                },
                Err(super::supervisor::AgentRouteError::NotReady) => {
                    *slot = OwnedRouteSlot::Pending(attachment);
                    return Ok(());
                }
                Err(error) => {
                    tracing::warn!(?error, "Agent production projection authorization failed");
                    return retire_pending_after_error(
                        attachment,
                        AgentProductionOwnerError::InvalidProjection,
                    );
                }
            };
            if identities.is_empty() {
                if projection_is_empty {
                    return attachment.retire().map_err(Into::into);
                }
                *slot = OwnedRouteSlot::Pending(attachment);
                return Ok(());
            }
            let actual = match handle.identities() {
                Ok(actual) => actual,
                Err(_) => {
                    return retire_pending_after_error(
                        attachment,
                        AgentProductionOwnerError::InvalidProjection,
                    );
                }
            };
            let actual = match normalized_identities(&actual) {
                Ok(actual) => actual,
                Err(error) => return retire_pending_after_error(attachment, error),
            };
            if identities != actual {
                tracing::warn!(
                    authorized_routes = identities.len(),
                    physical_routes = actual.len(),
                    "Agent production route identities mismatch"
                );
                return retire_pending_after_error(
                    attachment,
                    AgentProductionOwnerError::InvalidProjection,
                );
            }
            let (attachment, handle) = attachment.into_parts_with_identities(identities);
            let publication = supervisor.attach(attachment)?;
            *slot = OwnedRouteSlot::Published {
                handle,
                publication,
            };
            Ok(())
        }
        OwnedRouteSlot::Published {
            handle,
            publication,
        } => {
            let (identities, dormant_lag) = match handle.authorize_projection(head, projection) {
                Ok(identities) => match normalized_identities(&identities) {
                    Ok(identities) => (identities, false),
                    Err(error) => {
                        return detach_published_after_error(
                            supervisor,
                            slot,
                            handle,
                            publication,
                            error,
                        );
                    }
                },
                Err(super::supervisor::AgentRouteError::NotReady) => (Vec::new(), true),
                Err(_) => {
                    return detach_published_after_error(
                        supervisor,
                        slot,
                        handle,
                        publication,
                        AgentProductionOwnerError::InvalidProjection,
                    );
                }
            };
            if projection_is_empty && !dormant_lag {
                return match supervisor.detach(&publication) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        *slot = OwnedRouteSlot::Published {
                            handle,
                            publication,
                        };
                        supervisor.request_shutdown();
                        Err(error.into())
                    }
                };
            }
            let current = publication
                .snapshots()
                .iter()
                .map(|snapshot| snapshot.identity())
                .collect::<Vec<_>>();
            let current = match normalized_identities(&current) {
                Ok(current) => current,
                Err(error) => {
                    return detach_published_after_error(
                        supervisor,
                        slot,
                        handle,
                        publication,
                        error,
                    );
                }
            };
            let publication = if identities == current {
                publication
            } else {
                match supervisor.refresh(&publication, identities) {
                    Ok(publication) => publication,
                    Err(error) => {
                        *slot = OwnedRouteSlot::Published {
                            handle,
                            publication,
                        };
                        return Err(error.into());
                    }
                }
            };
            *slot = OwnedRouteSlot::Published {
                handle,
                publication,
            };
            Ok(())
        }
    }
}

fn retire_pending_after_error(
    attachment: AgentRouteHostAttachment,
    primary: AgentProductionOwnerError,
) -> Result<(), AgentProductionOwnerError> {
    match attachment.retire() {
        Ok(()) => Err(primary),
        Err(error) => Err(error.into()),
    }
}

fn detach_published_after_error(
    supervisor: &mut AgentSupervisorOwner,
    slot: &mut OwnedRouteSlot,
    handle: AgentRouteHostHandle,
    publication: AgentRoutePublication,
    primary: AgentProductionOwnerError,
) -> Result<(), AgentProductionOwnerError> {
    match supervisor.detach(&publication) {
        Ok(()) => Err(primary),
        Err(error) => {
            *slot = OwnedRouteSlot::Published {
                handle,
                publication,
            };
            supervisor.request_shutdown();
            Err(error.into())
        }
    }
}

fn normalized_identities(
    identities: &[AgentRouteIdentity],
) -> Result<Vec<AgentRouteIdentity>, AgentProductionOwnerError> {
    let mut identities = identities.to_vec();
    identities.sort_by_key(|identity| identity.key());
    if identities
        .windows(2)
        .any(|pair| pair[0].key() == pair[1].key())
    {
        return Err(AgentProductionOwnerError::InvalidProjection);
    }
    Ok(identities)
}

fn accept_head(
    accepted: Option<AuthorityProjectionHead>,
    proposed: AuthorityProjectionHead,
) -> Result<(), AgentProductionOwnerError> {
    if !proposed.is_valid() {
        return Err(AgentProductionOwnerError::InvalidProjection);
    }
    let Some(accepted) = accepted else {
        return Ok(());
    };
    match proposed.state_revision.cmp(&accepted.state_revision) {
        core::cmp::Ordering::Less => return Err(AgentProductionOwnerError::StaleHead),
        core::cmp::Ordering::Equal => {
            return (accepted == proposed)
                .then_some(())
                .ok_or(AgentProductionOwnerError::ConflictingHead);
        }
        core::cmp::Ordering::Greater => {}
    }
    // The signed state commitment covers the monotonic revision itself, so
    // a higher revision with an unchanged commitment is not a possible
    // authority state and must not be accepted as progress.
    if proposed.state_commitment == accepted.state_commitment {
        return Err(AgentProductionOwnerError::ConflictingHead);
    }
    let current = (
        accepted.epoch.get(),
        accepted.authorization_sequence.get(),
        accepted.administration_generation.get(),
    );
    let next = (
        proposed.epoch.get(),
        proposed.authorization_sequence.get(),
        proposed.administration_generation.get(),
    );
    let below = next.0 < current.0 || next.1 < current.1 || next.2 < current.2;
    if below {
        Err(AgentProductionOwnerError::ConflictingHead)
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn shutdown_raced_inventory_owner_for_test() -> (
    AgentProductionOwner,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::SyncSender<()>,
) {
    tests::held_inventory_owner_with_shutdown_error(AgentProductionOwnerError::ProjectionNotReady)
}

#[cfg(test)]
mod tests {
    struct HeldInventory {
        entered: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
        shutdown: Option<Arc<AtomicBool>>,
        shutdown_error: Option<AgentProductionOwnerError>,
    }

    impl AuthorityInventorySource for HeldInventory {
        fn set_shutdown_signal(&mut self, shutdown: Arc<AtomicBool>) {
            self.shutdown = Some(shutdown);
        }

        fn load_inventory(&mut self) -> Result<AgentAuthorityInventory, AgentProductionOwnerError> {
            self.entered.send(()).unwrap();
            let _ = self.release.recv_timeout(Duration::from_secs(5));
            if self
                .shutdown
                .as_ref()
                .is_some_and(|signal| signal.load(Ordering::Acquire))
            {
                Err(self
                    .shutdown_error
                    .unwrap_or(AgentProductionOwnerError::ShutdownRequested))
            } else {
                Err(AgentProductionOwnerError::InvalidProjection)
            }
        }
    }

    fn held_inventory_owner() -> (
        AgentProductionOwner,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        held_inventory_owner_with_error(None)
    }

    pub(super) fn held_inventory_owner_with_shutdown_error(
        error: AgentProductionOwnerError,
    ) -> (
        AgentProductionOwner,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        held_inventory_owner_with_error(Some(error))
    }

    fn held_inventory_owner_with_error(
        shutdown_error: Option<AgentProductionOwnerError>,
    ) -> (
        AgentProductionOwner,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        let (entered, observed) = std::sync::mpsc::sync_channel(1);
        let (release, wait) = std::sync::mpsc::sync_channel(1);
        let owner = AgentProductionOwner {
            node: NodeId([1; 32]),
            system_agent: AgentId([2; 32]),
            supervisor: Some(
                AgentSupervisorOwner::start(AgentSupervisorLimits::default()).unwrap(),
            ),
            system: OwnedRouteSlot::Empty,
            local: OwnedRouteSlot::Empty,
            local_by_agent: None,
            shared: OwnedRouteSlot::Empty,
            shared_by_agent: None,
            source: Box::new(HeldInventory {
                entered,
                release: wait,
                shutdown: None,
                shutdown_error,
            }),
            accepted_head: None,
            routes_verified: false,
            routes_need_quarantine: false,
            completed_local_publication: None,
            completed_local_install: None,
            reconcile_interval: Duration::from_secs(60),
            reconcile_after: Instant::now(),
            lifecycle: None,
        };
        (owner, observed, release)
    }

    #[test]
    fn held_inventory_does_not_block_node_ticks_or_shutdown_admission() {
        let (owner, entered, release) = held_inventory_owner();
        let handle = owner.handle();
        let mut node = crate::node::VosNode::new();
        node.attach_clean_agent_owner(owner).unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        let (tick, observed) = std::sync::mpsc::sync_channel(1);
        let routing = std::thread::spawn(move || {
            node.run_forever_with(|node| {
                node.shutdown();
                let _ = tick.try_send(());
            });
            node.collect_checked()
        });
        let progressed = observed.recv_timeout(Duration::from_secs(1));
        let admission_closed = !handle.is_running();
        // Release even after a failed observation so the test never leaks workers.
        let _ = release.send(());
        let result = routing.join().unwrap();
        assert!(
            progressed.is_ok(),
            "node routing waited for inventory execution"
        );
        assert!(
            admission_closed,
            "shutdown must hide admission before inventory returns"
        );
        assert!(result.is_ok());
    }

    struct FailedInventory(AgentProductionOwnerError);

    impl AuthorityInventorySource for FailedInventory {
        fn set_shutdown_signal(&mut self, _: Arc<AtomicBool>) {}

        fn load_inventory(&mut self) -> Result<AgentAuthorityInventory, AgentProductionOwnerError> {
            Err(self.0)
        }
    }

    #[test]
    fn initial_projection_unavailability_retains_owner_without_exposing_routes() {
        use super::super::supervisor::AgentRouteError;
        assert_eq!(
            projection_transport_error(AgentRouteError::NotReady),
            AgentProductionOwnerError::ProjectionNotReady
        );
        assert_eq!(
            projection_transport_error(AgentRouteError::Busy),
            AgentProductionOwnerError::ProjectionBusy
        );
        for error in [AgentRouteError::Unavailable, AgentRouteError::Rejected] {
            assert_eq!(
                projection_transport_error(error),
                AgentProductionOwnerError::ProjectionTransport
            );
        }
        let (mut owner, _, _) = held_inventory_owner();
        owner.source = Box::new(FailedInventory(
            AgentProductionOwnerError::ProjectionNotReady,
        ));
        for _ in 0..3 {
            let due = owner.reconcile_after;
            assert_eq!(owner.drive_if_due(due), Ok(false));
            assert!(owner.is_running());
            assert!(!owner.is_ready());
            assert!(owner.ingress().is_err());
            assert_eq!(owner.accepted_head, None);
            assert!(owner.needs_route_quarantine());
            owner.quarantine_routes().unwrap();
            assert!(!owner.needs_route_quarantine());
        }
        let retry = owner.reconcile_after;
        owner.source = Box::new(FailedInventory(
            AgentProductionOwnerError::InvalidProjection,
        ));
        assert_eq!(
            owner.drive_if_due(retry - Duration::from_millis(1)),
            Ok(false)
        );
        assert_eq!(
            owner.drive_if_due(retry),
            Err(AgentProductionOwnerError::InvalidProjection)
        );

        // A fresh, verified inventory can publish normally on the same owner.
        let descriptor = descriptor(1, AgentProfile::Shared, owner.node);
        let actor = actor(&descriptor, true);
        owner.system_agent = descriptor.identity.agent;
        owner.source = Box::new(client(
            vec![descriptor],
            vec![actor],
            head(1),
            Arc::new(Mutex::new(Vec::new())),
        ));
        assert_eq!(owner.drive_if_due(retry), Ok(true));
        assert!(owner.is_ready());
        owner.source = Box::new(FailedInventory(
            AgentProductionOwnerError::ProjectionNotReady,
        ));
        // A previously accepted head is retained only as an anti-rollback
        // anchor, never as permission to keep serving while the source lags.
        assert_eq!(
            owner.drive_if_due(owner.reconcile_after),
            Err(AgentProductionOwnerError::ProjectionNotReady)
        );
        assert!(owner.is_running());
        assert!(!owner.is_ready());
        assert!(owner.ingress().is_err());
        assert_eq!(owner.accepted_head, Some(head(1)));
        assert!(owner.needs_route_quarantine());
        owner.quarantine_routes().unwrap();
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn temporary_projection_failure_preserves_head_and_requires_quarantine_before_fresh_retry() {
        for failure in [
            AgentProductionOwnerError::ProjectionBusy,
            AgentProductionOwnerError::ProjectionNotReady,
        ] {
            let (mut owner, _, _) = held_inventory_owner();
            let system = descriptor(1, AgentProfile::Shared, owner.node);
            owner.system_agent = system.identity.agent;
            let fresh_source = || {
                Box::new(client(
                    vec![system.clone()],
                    vec![actor(&system, true)],
                    head(1),
                    Arc::new(Mutex::new(Vec::new())),
                )) as Box<dyn AuthorityInventorySource>
            };
            owner.source = fresh_source();
            owner.reconcile().unwrap();
            assert!(owner.is_ready());
            let accepted = owner.accepted_head;
            owner.source = Box::new(FailedInventory(failure));
            assert_eq!(owner.reconcile(), Err(failure));
            assert!(owner.is_running());
            assert!(!owner.is_ready());
            assert!(owner.ingress().is_err());
            assert_eq!(owner.accepted_head, accepted);
            assert!(owner.needs_route_quarantine());

            // Even a now-successful source must not bypass the worker's hiding
            // boundary. The ordinary retry deadline is not reset by early polls.
            let due = owner.reconcile_after;
            owner.source = fresh_source();
            assert_eq!(
                owner.reconcile(),
                Err(AgentProductionOwnerError::ProjectionBusy)
            );
            assert_eq!(owner.reconcile_after, due);
            owner.quarantine_routes().unwrap();
            assert!(!owner.needs_route_quarantine());
            assert_eq!(
                owner.drive_if_due(due - Duration::from_millis(1)),
                Ok(false)
            );
            assert!(!owner.is_ready());
            assert_eq!(owner.drive_if_due(due), Ok(true));
            assert!(owner.is_ready());
            assert_eq!(owner.accepted_head, accepted);
            owner.shutdown_and_join().unwrap();
        }
    }

    #[test]
    fn projection_busy_does_not_exempt_failed_fresh_validation() {
        for error in [
            AgentProductionOwnerError::ProjectionTransport,
            AgentProductionOwnerError::InvalidProjection,
            AgentProductionOwnerError::Authentication,
            AgentProductionOwnerError::RevokedCredential,
            AgentProductionOwnerError::ConflictingHead,
        ] {
            let (mut owner, _, _) = held_inventory_owner();
            owner.accepted_head = Some(head(1));
            owner.routes_verified = true;
            owner.source = Box::new(FailedInventory(AgentProductionOwnerError::ProjectionBusy));
            assert_eq!(
                owner.reconcile(),
                Err(AgentProductionOwnerError::ProjectionBusy)
            );
            owner.quarantine_routes().unwrap();
            owner.source = Box::new(FailedInventory(error));
            let due = owner.reconcile_after;
            assert_eq!(owner.drive_if_due(due), Err(error));
            assert!(!owner.is_ready());
            assert!(owner.ingress().is_err());
            assert_eq!(owner.accepted_head, Some(head(1)));
            owner.shutdown_and_join().unwrap();
        }
    }

    #[test]
    fn control_worker_bounds_pending_calls_and_rejects_them_on_shutdown() {
        use super::super::production_worker::AgentProductionWorker;
        let (owner, entered, release) = held_inventory_owner();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker = Arc::new(
            AgentProductionWorker::start(
                owner,
                shutdown.clone(),
                Arc::new(std::sync::RwLock::new(None)),
                Arc::new(AtomicBool::new(true)),
                Arc::new(super::super::local_lifecycle::LocalLifecycleQueue::default()),
            )
            .unwrap(),
        );
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        let (completed, results) = std::sync::mpsc::channel();
        let mut callers = Vec::new();
        for _ in 0..5 {
            let worker = worker.clone();
            let completed = completed.clone();
            callers.push(std::thread::spawn(move || {
                completed
                    .send(worker.call(|owner| owner.is_some()))
                    .unwrap();
            }));
        }
        let overflow = results.recv_timeout(Duration::from_secs(1));
        worker.request_shutdown();
        assert!(shutdown.load(Ordering::Acquire));
        let _ = release.send(());
        for caller in callers {
            caller.join().unwrap();
        }
        assert!(
            matches!(overflow, Ok(Err(_))),
            "fifth queued control must be refused"
        );
        for _ in 0..4 {
            assert_eq!(results.recv().unwrap(), Ok(false));
        }
        let worker = Arc::try_unwrap(worker).ok().unwrap();
        worker.shutdown_and_join().unwrap();
    }

    #[test]
    fn failed_inventory_stops_node_and_surfaces_through_collect() {
        let (owner, entered, release) = held_inventory_owner();
        let handle = owner.handle();
        let mut node = crate::node::VosNode::new();
        node.attach_clean_agent_owner(owner).unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        release.send(()).unwrap();
        node.run_forever();
        assert!(!handle.is_running());
        assert!(node.collect_checked().is_err());
    }

    #[test]
    fn node_idle_exit_waits_for_active_control_work() {
        let (owner, entered, release) = held_inventory_owner();
        let mut node = crate::node::VosNode::new();
        node.attach_clean_agent_owner(owner).unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        let (finished, observed) = std::sync::mpsc::sync_channel(1);
        let routing = std::thread::spawn(move || {
            node.run_until_idle(Duration::from_millis(20));
            let _ = finished.send(());
            node.collect_checked()
        });
        let early = observed.recv_timeout(Duration::from_millis(150));
        let _ = release.send(());
        let result = routing.join().unwrap();
        assert!(matches!(
            early,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(
            result.is_err(),
            "released invalid inventory still fails closed"
        );
    }

    #[test]
    fn panicked_control_closes_admission_and_is_reported_by_join() {
        use super::super::production_worker::AgentProductionWorker;
        let (mut owner, _entered, _release) = held_inventory_owner();
        owner.reconcile_after = Instant::now() + Duration::from_secs(60);
        let handle = owner.handle();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker = AgentProductionWorker::start(
            owner,
            shutdown.clone(),
            Arc::new(std::sync::RwLock::new(None)),
            Arc::new(AtomicBool::new(true)),
            Arc::new(super::super::local_lifecycle::LocalLifecycleQueue::default()),
        )
        .unwrap();
        assert!(
            worker
                .call::<()>(|owner| {
                    assert!(owner.is_some());
                    panic!("injected control failure");
                })
                .is_err()
        );
        assert!(worker.shutdown_and_join().is_err());
        assert!(shutdown.load(Ordering::Acquire));
        assert!(!handle.is_running());
    }

    use super::*;
    use core::num::NonZeroU64;
    use std::sync::{Arc, Mutex};

    use super::super::sdk::authority::{
        AgentAuthorityBinding, AuthorityBuiltinRole, AuthorityIngressAuthentication,
        AuthorityIssuer,
    };
    use super::super::sdk::contract::{ActorPackageContract, RuntimePackageContract};
    use super::super::sdk::{
        ActorEntry, ActorId, AgentIdentity, AgentReplica, BlobRef, DeploymentId, Hash,
        InstallationId, LaneSet, ProducerId, ProgramId, ReplicaRole, RuntimeCapabilities,
        RuntimeRequirements, SpaceId,
    };

    fn authority() -> AgentAuthorityBinding {
        let public_key = [0x91; 32];
        AgentAuthorityBinding {
            policy: Hash([0x92; 32]),
            issuer: AuthorityIssuer {
                principal: PrincipalId([0x93; 32]),
                actor: ActorId([0x94; 32]),
                deployment: DeploymentId([0x95; 32]),
                program: ProgramId([0x96; 32]),
                producer: ProducerId::of_public_key(&public_key),
            },
            public_key,
            initial_epoch: 1,
        }
    }

    fn descriptor(index: u64, profile: AgentProfile, node: NodeId) -> AgentDescriptor {
        let space = SpaceId([0x11; 32]);
        let mut owner = [0u8; 32];
        owner[..8].copy_from_slice(&index.saturating_add(1).to_be_bytes());
        owner[31] = 1;
        let owner = PrincipalId(owner);
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&index.saturating_add(2).to_be_bytes());
        nonce[31] = 2;
        let creation_nonce = Hash(nonce);
        let agent = AgentId::derive(space, owner, creation_nonce.as_bytes());
        let byte = u8::try_from(index % 200).unwrap().saturating_add(1);
        let descriptor = AgentDescriptor {
            identity: AgentIdentity {
                space,
                agent,
                owner,
                profile,
                runtime_deployment: DeploymentId([byte; 32]),
                runtime_program: ProgramId([byte.saturating_add(1); 32]),
                runtime_producer: ProducerId([byte.saturating_add(2); 32]),
                transition_producer: ProducerId([byte.saturating_add(3); 32]),
            },
            creation_nonce,
            authority: authority(),
            private_recovery: None,
            runtime_package: BlobRef::of_bytes(&index.to_be_bytes()),
            runtime_contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            replicas: vec![AgentReplica {
                node,
                principal: owner,
                role: ReplicaRole::Voter,
            }],
        };
        descriptor.validate().unwrap();
        descriptor
    }

    fn actor(descriptor: &AgentDescriptor, root_provenance: bool) -> AuthorityActorProjection {
        AuthorityActorProjection {
            agent: descriptor.identity.agent,
            entry: ActorEntry {
                actor: ActorId([0x41; 32]),
                name: "root".into(),
                parent: None,
                deployment: DeploymentId([0x42; 32]),
                program: ProgramId([0x43; 32]),
                package: BlobRef::of_bytes(b"actor-package"),
                agent_schema: BlobRef::of_bytes(b"actor-schema"),
                method_policy: BlobRef::of_bytes(b"actor-policy"),
                constructor_abi: Hash([0x44; 32]),
                installation_data: None,
                state_layout: Hash([0x45; 32]),
                lanes: LaneSet::ALL,
                suspended: false,
            },
            producer: ProducerId([0x46; 32]),
            contract: ActorPackageContract::canonical(),
            requirements: RuntimeRequirements {
                lanes: LaneSet::ALL,
                scheduling: false,
                proof_systems: super::super::sdk::ProofSystemSet::EMPTY,
            },
            root_provenance,
            installation_id: InstallationId([0x47; 32]),
            registry_reservation: Hash([0x48; 32]),
            install_request: Hash([0x49; 32]),
        }
    }

    fn head(counter: u64) -> AuthorityProjectionHead {
        AuthorityProjectionHead {
            state_revision: NonZeroU64::new(counter).unwrap(),
            epoch: NonZeroU64::new(counter).unwrap(),
            authorization_sequence: NonZeroU64::new(counter).unwrap(),
            administration_generation: NonZeroU64::new(counter).unwrap(),
            state_commitment: Hash([u8::try_from(counter).unwrap(); 32]),
        }
    }

    #[test]
    fn shared_handoff_guard_refuses_loss_of_a_known_projected_generation() {
        let descriptor = descriptor(2, AgentProfile::Shared, NodeId([0x31; 32]));
        let agent = descriptor.identity.agent;
        let projection = AgentAuthorityRouteProjection::new(
            descriptor.replica_generation(),
            descriptor,
            Vec::new(),
        )
        .unwrap();
        let projected = [projection];
        assert_eq!(
            validate_known_shared_presence([agent].into_iter(), [].into_iter(), &projected),
            Err(AgentProductionOwnerError::InvalidProjection)
        );
        assert_eq!(
            validate_known_shared_presence([agent].into_iter(), [agent].into_iter(), &projected),
            Ok(())
        );
        // A new desired member has never supplied a physical handle. An
        // authenticated directory removal may retire an existing member.
        assert_eq!(
            validate_known_shared_presence([].into_iter(), [].into_iter(), &projected),
            Ok(())
        );
        assert_eq!(
            validate_known_shared_presence([agent].into_iter(), [].into_iter(), &[]),
            Ok(())
        );
        // Presence of an unrelated physical member cannot conceal the loss.
        assert_eq!(
            validate_known_shared_presence(
                [agent].into_iter(),
                [AgentId([0x32; 32])].into_iter(),
                &projected,
            ),
            Err(AgentProductionOwnerError::InvalidProjection)
        );
    }

    fn fixed_three_linear_shared_descriptor(node: NodeId) -> AgentDescriptor {
        let mut descriptor = descriptor(2, AgentProfile::Shared, node);
        descriptor.capabilities.lanes = LaneSet::of(super::super::sdk::StateLane::Linear);
        let principal = descriptor.identity.owner;
        descriptor
            .replicas
            .extend([0x32, 0x33].map(|byte| AgentReplica {
                node: NodeId([byte; 32]),
                principal,
                role: ReplicaRole::Voter,
            }));
        descriptor.replicas.sort_by_key(|replica| replica.node);
        descriptor.validate().unwrap();
        descriptor
    }

    #[test]
    fn shared_handoff_never_defers_an_unknown_image_member() {
        let descriptor = fixed_three_linear_shared_descriptor(NodeId([0x31; 32]));
        let projection = AgentAuthorityRouteProjection::new(
            descriptor.replica_generation(),
            descriptor,
            Vec::new(),
        )
        .unwrap();
        assert!(!shared_handoff_projection_can_wait(&projection));
    }

    #[cfg(feature = "experimental-state-blocks")]
    fn pending_shared_descriptor(node: NodeId) -> AgentDescriptor {
        let mut descriptor = fixed_three_linear_shared_descriptor(node);
        descriptor.runtime_contract = RuntimePackageContract::experimental_state_blocks();
        descriptor.validate().unwrap();
        descriptor
    }

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn shared_handoff_deferral_is_only_for_supported_external_fixed_three() {
        fn can_wait(descriptor: AgentDescriptor) -> bool {
            let projection = AgentAuthorityRouteProjection::new(
                descriptor.replica_generation(),
                descriptor,
                Vec::new(),
            )
            .unwrap();
            shared_handoff_projection_can_wait(&projection)
        }

        let pending = pending_shared_descriptor(NodeId([0x31; 32]));
        assert!(can_wait(pending.clone()));
        let mut image = pending.clone();
        image.runtime_contract = RuntimePackageContract::canonical();
        assert!(!can_wait(image));
        let mut two_voters = pending.clone();
        two_voters.replicas.pop();
        assert!(!can_wait(two_voters));
        let mut observer = pending.clone();
        observer.replicas[2].role = ReplicaRole::Observer;
        assert!(!can_wait(observer));
        let mut extra_lanes = pending.clone();
        extra_lanes.capabilities.lanes = LaneSet::ALL;
        assert!(!can_wait(extra_lanes));
        let mut scheduling = pending;
        scheduling.capabilities.scheduling = true;
        assert!(!can_wait(scheduling));
    }

    fn target() -> AuthorityActorTarget {
        AuthorityActorTarget {
            space: SpaceId([0x11; 32]),
            system_agent: AgentId([0xfa; 32]),
            system_runtime_deployment: DeploymentId([0xfb; 32]),
            binding: authority(),
        }
    }

    struct TestAuthenticator {
        ordinal: u8,
    }

    impl AuthorityProjectionQueryAuthenticator for TestAuthenticator {
        fn expected_kind(&self) -> AuthorityCredentialKind {
            AuthorityCredentialKind::Api
        }

        fn authenticate(
            &mut self,
            authority: AuthorityActorTarget,
            selector: AuthorityProjectionSelector,
        ) -> Result<AuthorityProjectionQuery, AgentProductionOwnerError> {
            self.ordinal = self.ordinal.wrapping_add(1).max(1);
            let public_key = [0xa1; 32];
            Ok(AuthorityProjectionQuery {
                recovery: None,
                authority,
                credential: super::super::sdk::CredentialId::of_public_key(&public_key),
                nonce: Hash([self.ordinal; 32]),
                selector,
                authentication: AuthorityIngressAuthentication::ApiCredentialSignature {
                    credential_public_key: public_key,
                    signature: [0xa2; 64],
                },
            })
        }
    }

    struct FreshProjectionState {
        target: AuthorityActorTarget,
        events: Vec<&'static str>,
        queries: Vec<AuthorityProjectionQuery>,
        failures: Vec<(usize, AgentProductionOwnerError)>,
        invalid_reply: u8,
        invalid_authentication: u8,
        credential_public_key: Option<[u8; 32]>,
        page_cap: usize,
        descriptors: Vec<AgentDescriptor>,
        actors: Vec<AuthorityActorProjection>,
    }

    struct FreshProjectionTransport(Arc<Mutex<FreshProjectionState>>);

    impl AuthorityProjectionTransport for FreshProjectionTransport {
        fn target(&self) -> AuthorityActorTarget {
            self.0.lock().unwrap().target
        }

        fn dispatch(
            &mut self,
            mut query: AuthorityProjectionQuery,
        ) -> Result<Vec<u8>, AgentProductionOwnerError> {
            assert!(query.recovery.is_none());
            let mut state = self.0.lock().unwrap();
            state.events.push("dispatch");
            state.queries.push(query.clone());
            let ordinal = state.queries.len();
            if let Some(index) = state.failures.iter().position(|(at, _)| *at == ordinal) {
                return Err(state.failures.remove(index).1);
            }
            if state.invalid_reply == 1 {
                return Ok(b"not a canonical projection".to_vec());
            }
            if state.invalid_reply == 2 {
                query.nonce = Hash([0xff; 32]);
            }
            inventory_page_fixture(
                query,
                head(1),
                if state.invalid_reply == 3 {
                    PrincipalId([0xb7; 32])
                } else {
                    PrincipalId([0xa5; 32])
                },
                &state.descriptors,
                &state.actors,
                state.page_cap,
            )
        }
    }

    struct FreshProjectionAuthenticator {
        state: Arc<Mutex<FreshProjectionState>>,
        inner: TestAuthenticator,
    }

    impl AuthorityProjectionQueryAuthenticator for FreshProjectionAuthenticator {
        fn expected_kind(&self) -> AuthorityCredentialKind {
            AuthorityCredentialKind::Api
        }

        fn authenticate(
            &mut self,
            authority: AuthorityActorTarget,
            selector: AuthorityProjectionSelector,
        ) -> Result<AuthorityProjectionQuery, AgentProductionOwnerError> {
            let (public_key, invalid_authentication) = {
                let mut state = self.state.lock().unwrap();
                state.events.push("sign");
                (state.credential_public_key, state.invalid_authentication)
            };
            let mut query = self.inner.authenticate(authority, selector)?;
            if let Some(public_key) = public_key {
                query.credential = super::super::sdk::CredentialId::of_public_key(&public_key);
                query.authentication = AuthorityIngressAuthentication::ApiCredentialSignature {
                    credential_public_key: public_key,
                    signature: [0xa2; 64],
                };
            }
            match invalid_authentication {
                0 => (),
                1 => {
                    query.recovery = Some(
                        super::super::sdk::authority::AuthorityProjectionRecoveryDelegation {
                            generation: Hash([0xa3; 32]),
                            committee: Hash([0xa4; 32]),
                            accepted_slot: 10,
                            expires_at: 20,
                        },
                    );
                }
                2 => query.authority.system_runtime_deployment = DeploymentId([0xfc; 32]),
                3 => query.selector = AuthorityProjectionSelector::Credential,
                4 => query.nonce = Hash::ZERO,
                _ => unreachable!(),
            }
            Ok(query)
        }
    }

    fn fresh_projection_client(
        failures: Vec<(usize, AgentProductionOwnerError)>,
    ) -> (
        CleanAuthorityProjectionClient,
        Arc<Mutex<FreshProjectionState>>,
    ) {
        let state = Arc::new(Mutex::new(FreshProjectionState {
            target: target(),
            events: Vec::new(),
            queries: Vec::new(),
            failures,
            invalid_reply: 0,
            invalid_authentication: 0,
            credential_public_key: None,
            page_cap: usize::MAX,
            descriptors: Vec::new(),
            actors: Vec::new(),
        }));
        let client = CleanAuthorityProjectionClient::new(
            Box::new(FreshProjectionTransport(state.clone())),
            Box::new(FreshProjectionAuthenticator {
                state: state.clone(),
                inner: TestAuthenticator { ordinal: 0 },
            }),
        );
        (client, state)
    }

    #[test]
    fn production_inventory_hinted_transient_retry_requires_a_fresh_observation() {
        for error in [
            AgentProductionOwnerError::ProjectionBusy,
            AgentProductionOwnerError::ProjectionNotReady,
        ] {
            let (mut client, state) = fresh_projection_client(vec![(2, error)]);
            state.lock().unwrap().descriptors.push(descriptor(
                1,
                AgentProfile::Shared,
                NodeId([0x31; 32]),
            ));
            let original = client.load_inventory().unwrap();
            let private_hint = client.inventory.clone().unwrap();
            state.lock().unwrap().events.clear();

            // Complete cached data is only private retry material, never a
            // successful refresh or permission to serve a failed observation.
            assert_eq!(client.load_inventory(), Err(error));
            assert_eq!(client.inventory, Some(private_hint));
            assert_eq!(client.load_inventory().unwrap(), original);
            let state = state.lock().unwrap();
            assert_eq!(state.queries.len(), 3);
            assert_eq!(
                state.queries[1].selector,
                inventory_selector(Some(original.head))
            );
            assert_eq!(state.queries[1].selector, state.queries[2].selector);
            assert_ne!(state.queries[1].nonce, state.queries[2].nonce);
            assert!(state.queries.iter().all(|query| query.recovery.is_none()));
            assert_eq!(state.events, ["sign", "dispatch", "sign", "dispatch"]);
        }
    }

    #[test]
    fn production_inventory_hinted_retry_discards_fatal_invalid_or_changed_claims() {
        for (failure, invalid_reply, expected) in [
            (
                Some(AgentProductionOwnerError::Authentication),
                0,
                AgentProductionOwnerError::Authentication,
            ),
            (
                Some(AgentProductionOwnerError::ProjectionTransport),
                0,
                AgentProductionOwnerError::ProjectionTransport,
            ),
            (None, 1, AgentProductionOwnerError::InvalidProjection),
            (None, 2, AgentProductionOwnerError::InvalidProjection),
            (None, 3, AgentProductionOwnerError::InconsistentHead),
        ] {
            let (mut client, state) =
                fresh_projection_client(vec![(2, AgentProductionOwnerError::ProjectionBusy)]);
            let original = client.load_inventory().unwrap();
            assert_eq!(
                client.load_inventory(),
                Err(AgentProductionOwnerError::ProjectionBusy)
            );
            assert!(client.inventory.is_some());
            {
                let mut state = state.lock().unwrap();
                state.invalid_reply = invalid_reply;
                if let Some(error) = failure {
                    state.failures.push((3, error));
                }
            }
            assert_eq!(client.load_inventory(), Err(expected));
            assert!(client.inventory.is_none());
            state.lock().unwrap().invalid_reply = 0;
            assert_eq!(client.load_inventory().unwrap(), original);
            let state = state.lock().unwrap();
            assert_eq!(state.queries.len(), 4);
            assert_eq!(state.queries[1].selector, state.queries[2].selector);
            assert_ne!(state.queries[1].nonce, state.queries[2].nonce);
            assert_eq!(state.queries[3].selector, inventory_selector(None));
            assert_eq!(
                state
                    .events
                    .iter()
                    .filter(|event| **event == "sign")
                    .count(),
                4
            );
        }
    }

    #[test]
    fn production_inventory_hinted_retry_credential_rotation_requires_full_fresh_view() {
        let (mut client, state) =
            fresh_projection_client(vec![(2, AgentProductionOwnerError::ProjectionNotReady)]);
        state.lock().unwrap().descriptors.push(descriptor(
            1,
            AgentProfile::Shared,
            NodeId([0x31; 32]),
        ));
        let original = client.load_inventory().unwrap();
        assert_eq!(original.agents.len(), 1);
        let original_credential = client.inventory.as_ref().unwrap().0.query.credential;
        let public_key = [0xb6; 32];
        let rotated = super::super::sdk::CredentialId::of_public_key(&public_key);
        {
            let mut state = state.lock().unwrap();
            state.credential_public_key = Some(public_key);
            // Another credential can see different rows at the same head.
            state.descriptors.clear();
        }
        assert_eq!(
            client.load_inventory(),
            Err(AgentProductionOwnerError::ProjectionNotReady)
        );
        assert_eq!(
            client.inventory.as_ref().unwrap().0.query.credential,
            original_credential
        );
        let refreshed = client.load_inventory().unwrap();
        assert_eq!(refreshed.head, original.head);
        assert!(refreshed.agents.is_empty());
        assert_ne!(refreshed, original);
        assert_eq!(
            client.inventory.as_ref().unwrap().0.query.credential,
            rotated
        );
        let state = state.lock().unwrap();
        assert_eq!(state.queries.len(), 4);
        assert_eq!(state.queries[1].credential, rotated);
        assert_eq!(
            state.queries[1].selector,
            inventory_selector(Some(original.head))
        );
        assert_eq!(state.queries[1].selector, state.queries[2].selector);
        assert_ne!(state.queries[1].nonce, state.queries[2].nonce);
        assert_eq!(state.queries[3].credential, rotated);
        assert_eq!(state.queries[3].selector, inventory_selector(None));
        assert_ne!(state.queries[2].nonce, state.queries[3].nonce);
    }

    #[test]
    fn production_inventory_each_transient_retry_signs_a_fresh_non_delegated_query() {
        for error in [
            AgentProductionOwnerError::ProjectionBusy,
            AgentProductionOwnerError::ProjectionNotReady,
        ] {
            let (mut client, state) = fresh_projection_client(vec![(1, error)]);
            assert_eq!(client.load_inventory(), Err(error));
            assert!(client.inventory.is_none());
            client.load_inventory().unwrap();
            client.load_inventory().unwrap();
            let state = state.lock().unwrap();
            assert_eq!(
                state.events,
                ["sign", "dispatch", "sign", "dispatch", "sign", "dispatch"]
            );
            assert!(state.queries.iter().all(|query| query.recovery.is_none()));
            assert_ne!(state.queries[0].nonce, state.queries[1].nonce);
            assert_ne!(state.queries[1].nonce, state.queries[2].nonce);
        }
    }

    #[test]
    fn production_inventory_target_and_selector_changes_require_fresh_signing() {
        for change_target in [false, true] {
            let (mut client, state) =
                fresh_projection_client(vec![(1, AgentProductionOwnerError::ProjectionBusy)]);
            assert_eq!(
                client.query::<AuthorityInventoryProjectionPage>(inventory_selector(None)),
                Err(AgentProductionOwnerError::ProjectionBusy),
            );
            let selector = if change_target {
                state.lock().unwrap().target.system_runtime_deployment = DeploymentId([0xfc; 32]);
                inventory_selector(None)
            } else {
                inventory_selector(Some(head(1)))
            };
            let (query, _) = client
                .query::<AuthorityInventoryProjectionPage>(selector)
                .unwrap();
            let state = state.lock().unwrap();
            assert_eq!(query.authority, state.target);
            assert_eq!(query.selector, selector);
            assert_ne!(state.queries[0].nonce, state.queries[1].nonce);
            assert_eq!(state.events, ["sign", "dispatch", "sign", "dispatch"]);
        }
    }

    #[test]
    fn production_inventory_failed_later_page_restarts_fresh_without_partial_cache() {
        let (mut client, state) =
            fresh_projection_client(vec![(2, AgentProductionOwnerError::ProjectionBusy)]);
        let descriptor = descriptor(1, AgentProfile::Shared, NodeId([0x31; 32]));
        {
            let mut state = state.lock().unwrap();
            state.page_cap = 1;
            state.actors.push(actor(&descriptor, true));
            state.descriptors.push(descriptor);
        }
        assert_eq!(
            client.load_inventory(),
            Err(AgentProductionOwnerError::ProjectionBusy)
        );
        assert!(client.inventory.is_none());
        assert_eq!(client.load_inventory().unwrap().agents.len(), 1);
        let state = state.lock().unwrap();
        assert!(matches!(
            state.queries[1].selector,
            AuthorityProjectionSelector::Inventory { after: Some(_), .. },
        ));
        assert_eq!(state.queries[2].selector, inventory_selector(None));
        assert_ne!(state.queries[1].nonce, state.queries[2].nonce);
    }

    #[test]
    fn production_inventory_fatal_or_invalid_read_cannot_succeed_from_cache() {
        for error in [
            AgentProductionOwnerError::Authentication,
            AgentProductionOwnerError::ProjectionTransport,
            AgentProductionOwnerError::InvalidProjection,
            AgentProductionOwnerError::InconsistentHead,
            AgentProductionOwnerError::Lifecycle(
                super::super::shared_host::SharedAgentHostError::ScopeMismatch,
            ),
        ] {
            let (mut client, state) = fresh_projection_client(vec![(1, error)]);
            assert_eq!(client.load_inventory(), Err(error));
            assert!(client.inventory.is_none());
            client.load_inventory().unwrap();
            let state = state.lock().unwrap();
            assert_ne!(state.queries[0].nonce, state.queries[1].nonce);
        }
        for invalid_reply in [1, 2] {
            let (mut client, state) = fresh_projection_client(Vec::new());
            state.lock().unwrap().invalid_reply = invalid_reply;
            assert_eq!(
                client.load_inventory(),
                Err(AgentProductionOwnerError::InvalidProjection)
            );
            assert!(client.inventory.is_none());
            state.lock().unwrap().invalid_reply = 0;
            client.load_inventory().unwrap();
            let state = state.lock().unwrap();
            assert_ne!(state.queries[0].nonce, state.queries[1].nonce);
        }
    }

    #[test]
    fn production_inventory_rejects_delegated_or_substituted_authentication_before_dispatch() {
        for invalid_authentication in 1..=4 {
            let (mut client, state) = fresh_projection_client(Vec::new());
            state.lock().unwrap().invalid_authentication = invalid_authentication;
            assert_eq!(
                client.query::<AuthorityInventoryProjectionPage>(inventory_selector(None)),
                Err(AgentProductionOwnerError::Authentication)
            );
            assert_eq!(state.lock().unwrap().events, ["sign"]);
            assert!(state.lock().unwrap().queries.is_empty());
            assert!(client.inventory.is_none());
        }
    }

    struct ProjectionTransport {
        target: AuthorityActorTarget,
        head: AuthorityProjectionHead,
        actor_head: AuthorityProjectionHead,
        descriptors: Vec<AgentDescriptor>,
        actors: Vec<AuthorityActorProjection>,
        calls: Arc<Mutex<Vec<AuthorityProjectionSelector>>>,
        page_cap: usize,
    }

    impl AuthorityProjectionTransport for ProjectionTransport {
        fn target(&self) -> AuthorityActorTarget {
            self.target
        }

        fn dispatch(
            &mut self,
            query: AuthorityProjectionQuery,
        ) -> Result<Vec<u8>, AgentProductionOwnerError> {
            self.calls.lock().unwrap().push(query.selector);
            let changing = self.head != self.actor_head;
            let continuation = matches!(
                query.selector,
                AuthorityProjectionSelector::Inventory { after: Some(_), .. }
            );
            inventory_page_fixture(
                query,
                if changing && continuation {
                    self.actor_head
                } else {
                    self.head
                },
                PrincipalId([0xb1; 32]),
                &self.descriptors,
                &self.actors,
                if changing { 1 } else { self.page_cap },
            )
        }
    }

    fn inventory_selector(
        known_head: Option<AuthorityProjectionHead>,
    ) -> AuthorityProjectionSelector {
        AuthorityProjectionSelector::Inventory {
            after: None,
            limit: MAX_AUTHORITY_INVENTORY_PAGE_ENTRIES as u16,
            known_head,
        }
    }

    fn client(
        descriptors: Vec<AgentDescriptor>,
        actors: Vec<AuthorityActorProjection>,
        actor_head: AuthorityProjectionHead,
        calls: Arc<Mutex<Vec<AuthorityProjectionSelector>>>,
    ) -> CleanAuthorityProjectionClient {
        CleanAuthorityProjectionClient::new(
            Box::new(ProjectionTransport {
                page_cap: usize::MAX,
                target: target(),
                head: head(1),
                actor_head,
                descriptors,
                actors,
                calls,
            }),
            Box::new(TestAuthenticator { ordinal: 0 }),
        )
    }

    #[cfg(feature = "experimental-state-blocks")]
    #[test]
    fn shared_handoff_keeps_owner_running_without_creating_a_member_route() {
        use super::super::shared_host::SharedAgentHostError;

        struct UnadmittedShared;
        impl super::super::local_lifecycle::NativeLocalLifecycle for UnadmittedShared {
            fn management_admission_held(&self) -> Result<bool, SharedAgentHostError> {
                Ok(false)
            }
            fn shared_generations(
                &self,
            ) -> Result<
                Option<Vec<crate::network::shared_agent::SharedAgentRouteHandle>>,
                SharedAgentHostError,
            > {
                Ok(Some(Vec::new()))
            }
            fn node(&self) -> Result<NodeId, SharedAgentHostError> {
                unreachable!()
            }
            fn system_attachment(
                &self,
                _: usize,
            ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
                unreachable!()
            }
            fn local_attachment(
                &self,
                _: usize,
            ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
                unreachable!()
            }
            fn create(
                &mut self,
                _: AgentDescriptor,
                _: super::super::sdk::authority::AuthorityCredentialCall,
                _: super::super::package_admission::AdmittedRuntimePackage,
            ) -> Result<
                (
                    AgentId,
                    super::super::sdk::authority::ManagementApplicationAck,
                ),
                SharedAgentHostError,
            > {
                unreachable!()
            }
        }

        let node = NodeId([0x31; 32]);
        let system = descriptor(1, AgentProfile::Shared, node);
        let pending = pending_shared_descriptor(node);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let (mut owner, _, _) = held_inventory_owner();
        owner.node = node;
        owner.system_agent = system.identity.agent;
        owner.lifecycle = Some((Box::new(UnadmittedShared), 1));
        owner.source = Box::new(client(
            vec![system.clone()],
            vec![actor(&system, true)],
            head(1),
            calls.clone(),
        ));
        assert_eq!(owner.drive_if_due(owner.reconcile_after), Ok(true));
        assert_eq!(owner.accepted_head, Some(head(1)));

        let new_inventory = |member: AgentDescriptor, revision| {
            CleanAuthorityProjectionClient::new(
                Box::new(ProjectionTransport {
                    page_cap: usize::MAX,
                    target: target(),
                    head: head(revision),
                    actor_head: head(revision),
                    descriptors: vec![system.clone(), member],
                    actors: vec![actor(&system, true)],
                    calls: calls.clone(),
                }),
                Box::new(TestAuthenticator { ordinal: 0 }),
            )
        };
        owner.source = Box::new(new_inventory(pending.clone(), 2));
        for _ in 0..3 {
            assert_eq!(owner.drive_if_due(owner.reconcile_after), Ok(true));
            assert!(owner.is_running());
            assert_eq!(owner.accepted_head, Some(head(2)));
            assert!(owner.shared_by_agent.as_ref().unwrap().is_empty());
            assert!(owner.handle().snapshots().unwrap().is_empty());
        }
        // This is an owner-control regression, not fabricated physical
        // readiness. No System attachment or member admission was minted.
        assert!(owner.ingress().is_err());

        let mut image = pending;
        image.runtime_contract = RuntimePackageContract::canonical();
        owner.source = Box::new(new_inventory(image, 3));
        assert_eq!(
            owner.drive_if_due(owner.reconcile_after),
            Err(AgentProductionOwnerError::InvalidProjection)
        );
        assert_eq!(owner.accepted_head, Some(head(2)));
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn reconciliation_overrun_waits_a_full_interval_before_running_again() {
        check_reconciliation_deadline(false);
    }

    #[test]
    fn inventory_stream_rejects_incomplete_or_substituted_rows_without_reusing_cache() {
        struct HostileTransport {
            inner: ProjectionTransport,
            mode: Arc<std::sync::atomic::AtomicU8>,
        }
        impl AuthorityProjectionTransport for HostileTransport {
            fn target(&self) -> AuthorityActorTarget {
                self.inner.target()
            }
            fn dispatch(
                &mut self,
                query: AuthorityProjectionQuery,
            ) -> Result<Vec<u8>, AgentProductionOwnerError> {
                let mode = self.mode.load(Ordering::Acquire);
                if mode != 0 {
                    self.inner.head = head(2);
                    self.inner.actor_head = head(2);
                }
                self.inner.page_cap = if mode >= 8 { 1 } else { usize::MAX };
                let continuation = matches!(
                    query.selector,
                    AuthorityProjectionSelector::Inventory { after: Some(_), .. }
                );
                if mode == 9 && continuation {
                    return Err(AgentProductionOwnerError::ProjectionTransport);
                }
                let bytes = self.inner.dispatch(query)?;
                let mut page = AuthorityInventoryProjectionPage::decode(&bytes).unwrap();
                match mode {
                    1 => {
                        page.entries.remove(0);
                    }
                    2 => page
                        .entries
                        .retain(|entry| !matches!(entry, AuthorityInventoryEntry::Replica { .. })),
                    3 => {
                        let AuthorityInventoryEntry::Replica { replica, .. } = &mut page.entries[1]
                        else {
                            unreachable!()
                        };
                        replica.node = NodeId([0xfe; 32]); // wrong committed roster
                    }
                    4 => {
                        let mut extra = page.entries[1].clone();
                        let AuthorityInventoryEntry::Replica { replica, .. } = &mut extra else {
                            unreachable!()
                        };
                        replica.node = NodeId([0xfe; 32]);
                        page.entries.insert(2, extra); // exceeds replica_count
                    }
                    5 => {
                        let AuthorityInventoryEntry::Actor(actor) = &mut page.entries[2] else {
                            unreachable!()
                        };
                        actor.agent = AgentId([0xff; 32]);
                    }
                    6 => {
                        let AuthorityInventoryEntry::Agent(row) = &mut page.entries[0] else {
                            unreachable!()
                        };
                        row.capabilities.max_actors = 1;
                        let mut extra = page.entries[2].clone();
                        let AuthorityInventoryEntry::Actor(actor) = &mut extra else {
                            unreachable!()
                        };
                        actor.entry.actor = super::super::sdk::ActorId([0xfe; 32]);
                        actor.entry.name = "extra".into();
                        page.entries.push(extra);
                        page.entries.sort_by_key(AuthorityInventoryEntry::cursor);
                    }
                    7 => page.credential.query.nonce = super::super::sdk::Hash([0xee; 32]),
                    8 if continuation => page.credential.operation_request_high_water += 1,
                    10 => {
                        if let Some(AuthorityInventoryEntry::Agent(row)) = page.entries.first() {
                            // Canonical, terminal descriptor-only page: a
                            // producer cannot make a missing roster look done.
                            page.entries = vec![AuthorityInventoryEntry::Agent(row.clone())];
                            page.next = None;
                        }
                    }
                    _ => {}
                }
                page.encode()
                    .map_err(|_| AgentProductionOwnerError::InvalidProjection)
            }
        }
        for fault in 1..=10 {
            let descriptor = descriptor(1, AgentProfile::Shared, NodeId([0x31; 32]));
            let actors = vec![actor(&descriptor, true)];
            let mode = Arc::new(std::sync::atomic::AtomicU8::new(0));
            let mut source = CleanAuthorityProjectionClient::new(
                Box::new(HostileTransport {
                    inner: ProjectionTransport {
                        target: target(),
                        head: head(1),
                        actor_head: head(1),
                        descriptors: vec![descriptor],
                        actors,
                        calls: Arc::new(Mutex::new(Vec::new())),
                        page_cap: usize::MAX,
                    },
                    mode: mode.clone(),
                }),
                Box::new(TestAuthenticator { ordinal: 0 }),
            );
            source.load_inventory().unwrap();
            assert!(source.inventory.is_some());
            mode.store(fault, Ordering::Release);
            let expected = match fault {
                8 => AgentProductionOwnerError::InconsistentHead,
                9 => AgentProductionOwnerError::ProjectionTransport,
                _ => AgentProductionOwnerError::InvalidProjection,
            };
            assert_eq!(source.load_inventory(), Err(expected), "fault {fault}");
            assert!(
                source.inventory.is_none(),
                "fault {fault} retained stale inventory"
            );
            mode.store(0, Ordering::Release);
            assert_eq!(source.load_inventory().unwrap().head, head(2));
        }
    }

    #[test]
    fn inventory_reuse_requires_fresh_credential_and_exact_complete_head() {
        let node = NodeId([0x31; 32]);
        let descriptor = descriptor(1, AgentProfile::Shared, node);
        let actor = actor(&descriptor, true);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut source = client(vec![descriptor], vec![actor], head(1), calls.clone());
        let original = source.load_inventory().unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(source.load_inventory().unwrap(), original);
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert_eq!(
            calls.lock().unwrap().last(),
            Some(&inventory_selector(Some(head(1))))
        );

        // Neither another Authority target nor another credential may reuse
        // a prior principal's pages, even at an otherwise equal head.
        source
            .inventory
            .as_mut()
            .unwrap()
            .0
            .query
            .authority
            .system_agent = AgentId([0x91; 32]);
        assert_eq!(source.load_inventory().unwrap(), original);
        assert_eq!(calls.lock().unwrap().len(), 3);
        source.inventory.as_mut().unwrap().0.query.credential =
            super::super::sdk::CredentialId([0x92; 32]);
        assert_eq!(source.load_inventory().unwrap(), original);
        assert_eq!(calls.lock().unwrap().len(), 5);
        source.inventory.as_mut().unwrap().1.head = head(2);
        assert_eq!(source.load_inventory().unwrap(), original);
        assert_eq!(calls.lock().unwrap().len(), 6);

        // Equal head with contradictory claims is invalid, not a cache hit
        // and not an excuse to return previously authorized pages.
        source.inventory.as_mut().unwrap().0.principal = PrincipalId([0x93; 32]);
        assert_eq!(
            source.load_inventory(),
            Err(AgentProductionOwnerError::InconsistentHead)
        );
        assert!(source.inventory.is_none());
        assert_eq!(source.load_inventory().unwrap(), original);
        assert_eq!(calls.lock().unwrap().len(), 8);
    }

    #[test]
    fn two_agent_inventory_reuses_only_unchanged_head_and_observes_install() {
        struct MutableTransport(Arc<Mutex<ProjectionTransport>>);

        impl AuthorityProjectionTransport for MutableTransport {
            fn target(&self) -> AuthorityActorTarget {
                self.0.lock().unwrap().target()
            }

            fn dispatch(
                &mut self,
                query: AuthorityProjectionQuery,
            ) -> Result<Vec<u8>, AgentProductionOwnerError> {
                self.0.lock().unwrap().dispatch(query)
            }
        }

        let node = NodeId([0x31; 32]);
        let first = descriptor(1, AgentProfile::Shared, node);
        let second = descriptor(2, AgentProfile::Shared, node);
        let installed = actor(&second, true);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let transport = Arc::new(Mutex::new(ProjectionTransport {
            target: target(),
            head: head(1),
            actor_head: head(1),
            descriptors: vec![first.clone(), second.clone()],
            actors: vec![actor(&first, true)],
            calls: calls.clone(),
            page_cap: usize::MAX,
        }));
        let mut source = CleanAuthorityProjectionClient::new(
            Box::new(MutableTransport(transport.clone())),
            Box::new(TestAuthenticator { ordinal: 0 }),
        );

        let original = source.load_inventory().unwrap();
        assert_eq!(original.agents.len(), 2);
        let initial_queries = calls.lock().unwrap().clone();
        // Credential + both descriptors, replica sets and actor sets in one
        // bounded execution, versus six independent calls before the cutover.
        assert_eq!(initial_queries, vec![inventory_selector(None)]);
        calls.lock().unwrap().clear();
        assert_eq!(source.load_inventory().unwrap(), original);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![inventory_selector(Some(head(1)))]
        );

        // Change the transport's real state, not the client's cached head.
        // An Install must invalidate reuse even if descriptors are unchanged.
        {
            let mut state = transport.lock().unwrap();
            state.head = head(2);
            state.actor_head = head(2);
            state.actors.push(installed.clone());
        }
        calls.lock().unwrap().clear();
        let refreshed = source.load_inventory().unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            vec![inventory_selector(Some(head(1)))]
        );
        assert_eq!(refreshed.head, head(2));
        let mut expected = original;
        expected.head = head(2);
        expected.agents[1] = AgentAuthorityRouteProjection::new(
            second.replica_generation(),
            second,
            vec![installed],
        )
        .unwrap();
        assert_eq!(refreshed, expected);

        calls.lock().unwrap().clear();
        assert_eq!(source.load_inventory().unwrap(), refreshed);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![inventory_selector(Some(head(2)))]
        );
    }

    #[test]
    fn inventory_shutdown_stops_between_pages_and_discards_partial_cache() {
        struct StoppingTransport {
            inner: ProjectionTransport,
            shutdown: Arc<AtomicBool>,
            armed: Arc<AtomicBool>,
        }
        impl AuthorityProjectionTransport for StoppingTransport {
            fn target(&self) -> AuthorityActorTarget {
                self.inner.target()
            }
            fn dispatch(
                &mut self,
                query: AuthorityProjectionQuery,
            ) -> Result<Vec<u8>, AgentProductionOwnerError> {
                let stop = matches!(
                    query.selector,
                    AuthorityProjectionSelector::Inventory { after: Some(_), .. }
                ) && self.armed.load(Ordering::Acquire);
                let result = self.inner.dispatch(query);
                if stop {
                    self.shutdown.store(true, Ordering::Release);
                }
                result
            }
        }
        let node = NodeId([0x31; 32]);
        let descriptor = descriptor(1, AgentProfile::Shared, node);
        let actor = actor(&descriptor, true);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(true));
        let armed = Arc::new(AtomicBool::new(true));
        let mut source = CleanAuthorityProjectionClient::new(
            Box::new(StoppingTransport {
                inner: ProjectionTransport {
                    page_cap: 1,
                    target: target(),
                    head: head(1),
                    actor_head: head(1),
                    descriptors: vec![descriptor],
                    actors: vec![actor],
                    calls: calls.clone(),
                },
                shutdown: shutdown.clone(),
                armed: armed.clone(),
            }),
            Box::new(TestAuthenticator { ordinal: 0 }),
        );
        source.set_shutdown_signal(shutdown.clone());
        assert_eq!(
            source.load_inventory(),
            Err(AgentProductionOwnerError::ShutdownRequested)
        );
        assert!(calls.lock().unwrap().is_empty());
        shutdown.store(false, Ordering::Release);
        assert_eq!(
            source.load_inventory(),
            Err(AgentProductionOwnerError::ShutdownRequested)
        );
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert!(source.inventory.is_none());
        armed.store(false, Ordering::Release);
        shutdown.store(false, Ordering::Release);
        assert_eq!(source.load_inventory().unwrap().agents.len(), 1);
        assert!(source.inventory.is_some());
        let completed_calls = calls.lock().unwrap().len();
        shutdown.store(true, Ordering::Release);
        assert_eq!(
            source.load_inventory(),
            Err(AgentProductionOwnerError::ShutdownRequested)
        );
        assert_eq!(calls.lock().unwrap().len(), completed_calls);
        assert!(source.inventory.is_none());
    }

    #[test]
    fn inventory_reuse_never_masks_revocation_kind_or_transport_failure() {
        use std::sync::atomic::{AtomicU8, Ordering};
        struct ControlledTransport {
            inner: ProjectionTransport,
            mode: Arc<AtomicU8>,
        }
        impl AuthorityProjectionTransport for ControlledTransport {
            fn target(&self) -> AuthorityActorTarget {
                self.inner.target()
            }
            fn dispatch(
                &mut self,
                query: AuthorityProjectionQuery,
            ) -> Result<Vec<u8>, AgentProductionOwnerError> {
                let mode = self.mode.load(Ordering::Relaxed);
                if mode == 3 {
                    return Err(AgentProductionOwnerError::ProjectionTransport);
                }
                if mode == 4 {
                    self.inner.head = head(2);
                    self.inner.actor_head = head(2);
                }
                let bytes = self.inner.dispatch(query)?;
                let mut projection = AuthorityInventoryProjectionPage::decode(&bytes).unwrap();
                match mode {
                    1 => {
                        projection.credential.status = AuthorityCredentialStatus::Revoked;
                        projection.unchanged = false;
                        projection.entries.clear();
                        projection.next = None;
                    }
                    2 => projection.credential.kind = AuthorityCredentialKind::Ssh,
                    _ => {}
                }
                projection
                    .encode()
                    .map_err(|_| AgentProductionOwnerError::InvalidProjection)
            }
        }
        let node = NodeId([0x31; 32]);
        let descriptor = descriptor(1, AgentProfile::Shared, node);
        let actor = actor(&descriptor, true);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mode = Arc::new(AtomicU8::new(0));
        let mut source = CleanAuthorityProjectionClient::new(
            Box::new(ControlledTransport {
                inner: ProjectionTransport {
                    page_cap: usize::MAX,
                    target: target(),
                    head: head(1),
                    actor_head: head(1),
                    descriptors: vec![descriptor],
                    actors: vec![actor],
                    calls: calls.clone(),
                },
                mode: mode.clone(),
            }),
            Box::new(TestAuthenticator { ordinal: 0 }),
        );
        source.load_inventory().unwrap();
        for (value, error) in [
            (1, AgentProductionOwnerError::RevokedCredential),
            (2, AgentProductionOwnerError::WrongCredentialKind),
            (3, AgentProductionOwnerError::ProjectionTransport),
        ] {
            mode.store(value, Ordering::Relaxed);
            assert_eq!(source.load_inventory(), Err(error));
            assert!(source.inventory.is_none());
            mode.store(0, Ordering::Relaxed);
            let before = calls.lock().unwrap().len();
            source.load_inventory().unwrap();
            assert_eq!(calls.lock().unwrap().len(), before + 1);
        }
        mode.store(4, Ordering::Relaxed);
        let before = calls.lock().unwrap().len();
        assert_eq!(source.load_inventory().unwrap().head, head(2));
        assert_eq!(calls.lock().unwrap().len(), before + 1);
        source.load_inventory().unwrap();
        assert_eq!(calls.lock().unwrap().len(), before + 2);
    }

    #[test]
    fn install_delivery_requires_exact_active_local_identity() {
        let key = AgentRouteKey::new(SpaceId([1; 32]), AgentId([2; 32]), ActorId([3; 32])).unwrap();
        let runtime = DeploymentId([4; 32]);
        let deployment = DeploymentId([5; 32]);
        let program = ProgramId([6; 32]);
        let identity = AgentRouteIdentity::new(
            key,
            Hash([7; 32]),
            runtime,
            deployment,
            program,
            AgentProfile::Local,
        )
        .unwrap();
        assert!(installed_local_route_matches(
            Some(identity),
            key,
            runtime,
            deployment,
            program
        ));
        assert!(!installed_local_route_matches(
            None, key, runtime, deployment, program
        ));
        let other_key =
            AgentRouteKey::new(SpaceId([1; 32]), AgentId([2; 32]), ActorId([8; 32])).unwrap();
        for wrong in [
            AgentRouteIdentity::new(
                other_key,
                Hash([7; 32]),
                runtime,
                deployment,
                program,
                AgentProfile::Local,
            )
            .unwrap(),
            AgentRouteIdentity::new(
                key,
                Hash([7; 32]),
                DeploymentId([8; 32]),
                deployment,
                program,
                AgentProfile::Local,
            )
            .unwrap(),
            AgentRouteIdentity::new(
                key,
                Hash([7; 32]),
                runtime,
                DeploymentId([8; 32]),
                program,
                AgentProfile::Local,
            )
            .unwrap(),
            AgentRouteIdentity::new(
                key,
                Hash([7; 32]),
                runtime,
                deployment,
                ProgramId([8; 32]),
                AgentProfile::Local,
            )
            .unwrap(),
            AgentRouteIdentity::new(
                key,
                Hash([7; 32]),
                runtime,
                deployment,
                program,
                AgentProfile::Shared,
            )
            .unwrap(),
        ] {
            assert!(!installed_local_route_matches(
                Some(wrong),
                key,
                runtime,
                deployment,
                program
            ));
        }
    }

    #[test]
    fn completed_install_requires_exact_ack_head_attachment_and_incarnation() {
        let key = AgentRouteKey::new(SpaceId([1; 32]), AgentId([2; 32]), ActorId([3; 32])).unwrap();
        let identity = |incarnation| {
            AgentRouteIdentity::new(
                key,
                Hash([incarnation; 32]),
                DeploymentId([4; 32]),
                DeploymentId([5; 32]),
                ProgramId([6; 32]),
                AgentProfile::Local,
            )
            .unwrap()
        };
        let ack = Hash([0x31; 32]);
        let prior = Some((ack, head(1), identity(7)));
        assert!(completed_local_install_matches(
            prior,
            ack,
            Some(head(1)),
            true,
            Some(identity(7))
        ));
        for (previous, acknowledgement, accepted, attached, route) in [
            (None, ack, Some(head(1)), true, Some(identity(7))),
            (
                prior,
                Hash([0x32; 32]),
                Some(head(1)),
                true,
                Some(identity(7)),
            ),
            (prior, ack, None, true, Some(identity(7))),
            (prior, ack, Some(head(2)), true, Some(identity(7))),
            (prior, ack, Some(head(1)), false, Some(identity(7))),
            (prior, ack, Some(head(1)), true, None),
            (prior, ack, Some(head(1)), true, Some(identity(8))),
        ] {
            assert!(!completed_local_install_matches(
                previous,
                acknowledgement,
                accepted,
                attached,
                route
            ));
        }
    }

    #[test]
    fn completed_local_delivery_requires_exact_response_head_and_attachment() {
        let acknowledgement = super::super::sdk::Hash([0x31; 32]);
        let prior = Some((acknowledgement, head(1)));
        assert!(completed_local_publication_matches(
            prior,
            acknowledgement,
            Some(head(1)),
            true
        ));
        assert!(!completed_local_publication_matches(
            None,
            acknowledgement,
            Some(head(1)),
            true
        ));
        assert!(!completed_local_publication_matches(
            prior,
            acknowledgement,
            None,
            true
        ));
        assert!(!completed_local_publication_matches(
            prior,
            acknowledgement,
            Some(head(2)),
            true
        ));
        assert!(!completed_local_publication_matches(
            prior,
            super::super::sdk::Hash([0x32; 32]),
            Some(head(1)),
            true
        ));
        assert!(!completed_local_publication_matches(
            prior,
            acknowledgement,
            Some(head(1)),
            false
        ));
    }

    #[test]
    fn lifecycle_reconciliation_defers_the_next_periodic_run() {
        check_reconciliation_deadline(true);
    }

    #[test]
    fn shared_lifecycle_continuations_forward_without_publishing_readiness() {
        use super::super::genesis::AgentGenesisLocator;
        use super::super::shared_host::SharedAgentHostError;

        struct RetainedShared {
            locator: AgentGenesisLocator,
            calls: Arc<Mutex<Vec<&'static str>>>,
        }
        impl super::super::local_lifecycle::NativeLocalLifecycle for RetainedShared {
            fn node(&self) -> Result<NodeId, SharedAgentHostError> {
                unreachable!()
            }
            fn system_attachment(
                &self,
                _: usize,
            ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
                unreachable!()
            }
            fn local_attachment(
                &self,
                _: usize,
            ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
                unreachable!()
            }
            fn create(
                &mut self,
                _: AgentDescriptor,
                _: super::super::sdk::authority::AuthorityCredentialCall,
                _: super::super::package_admission::AdmittedRuntimePackage,
            ) -> Result<
                (
                    AgentId,
                    super::super::sdk::authority::ManagementApplicationAck,
                ),
                SharedAgentHostError,
            > {
                unreachable!()
            }
            fn prepare_shared_create(
                &mut self,
                locator: AgentGenesisLocator,
            ) -> Result<
                super::super::clean_bootstrap::PreparedSharedGenesisEndorsement,
                SharedAgentHostError,
            > {
                assert_eq!(locator, self.locator);
                self.calls.lock().unwrap().push("prepare");
                Err(SharedAgentHostError::CapacityExhausted)
            }
            fn complete_shared_create(
                &mut self,
                locator: AgentGenesisLocator,
            ) -> Result<super::super::sdk::authority::ManagementApplicationAck, SharedAgentHostError>
            {
                assert_eq!(locator, self.locator);
                self.calls.lock().unwrap().push("complete");
                Err(SharedAgentHostError::Conflict)
            }
        }

        let node = NodeId([0x31; 32]);
        let descriptor = descriptor(1, AgentProfile::Shared, node);
        let locator = AgentGenesisLocator {
            space: crate::service::SpaceId(descriptor.identity.space.0),
            agent: crate::service::AgentId(descriptor.identity.agent.0),
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let inventory_calls = Arc::new(Mutex::new(Vec::new()));
        let mut owner = AgentProductionOwner {
            node,
            system_agent: descriptor.identity.agent,
            supervisor: Some(
                AgentSupervisorOwner::start(AgentSupervisorLimits::default()).unwrap(),
            ),
            system: OwnedRouteSlot::Empty,
            local: OwnedRouteSlot::Empty,
            local_by_agent: None,
            shared: OwnedRouteSlot::Empty,
            shared_by_agent: None,
            source: Box::new(client(
                vec![descriptor.clone()],
                vec![actor(&descriptor, true)],
                head(1),
                inventory_calls.clone(),
            )),
            accepted_head: None,
            routes_verified: false,
            routes_need_quarantine: false,
            completed_local_publication: None,
            completed_local_install: None,
            reconcile_interval: Duration::from_secs(60),
            reconcile_after: Instant::now(),
            lifecycle: Some((
                Box::new(RetainedShared {
                    locator,
                    calls: calls.clone(),
                }),
                1,
            )),
        };
        assert!(!owner.is_ready());
        assert!(matches!(
            owner.prepare_shared_create(locator),
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::CapacityExhausted
            ))
        ));
        assert!(matches!(
            owner.endorse_shared_create(locator),
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::Unavailable
            ))
        ));
        // A backend without these optional methods cannot grant publication or
        // initialization merely because the production adapter exposes them.
        assert!(matches!(
            owner.publish_shared_create(locator, Vec::new()),
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::Unavailable
            ))
        ));
        assert!(matches!(
            owner.initialize_shared_management(locator),
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::Unavailable
            ))
        ));
        assert!(matches!(
            owner.complete_shared_install(locator),
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::Unavailable
            ))
        ));
        assert!(matches!(
            owner.complete_shared_create(locator),
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::Conflict
            ))
        ));
        assert_eq!(*calls.lock().unwrap(), ["prepare", "complete"]);
        assert!(inventory_calls.lock().unwrap().is_empty());
        assert!(owner.accepted_head.is_none());
        assert!(!owner.is_ready());
        owner.request_shutdown();
        assert!(matches!(
            owner.prepare_shared_create(locator),
            Err(AgentProductionOwnerError::ShutdownRequested)
        ));
        assert!(matches!(
            owner.endorse_shared_create(locator),
            Err(AgentProductionOwnerError::ShutdownRequested)
        ));
        assert_eq!(*calls.lock().unwrap(), ["prepare", "complete"]);
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    fn queued_exact_shared_create_reuses_retained_continuation_after_busy_quarantine() {
        use super::super::genesis::AgentGenesisLocator;
        use super::super::local_lifecycle::{
            LocalLifecycleQueue, NativeLocalLifecycle, PendingLocalLifecycle,
            SharedCreateSubmission,
        };
        use super::super::shared_host::SharedAgentHostError;

        // Owner ordering only: the continuation deliberately stops at prepare,
        // never fabricating application, quorum, finality or public readiness.
        struct Retained {
            submission: SharedCreateSubmission,
            calls: Arc<Mutex<Vec<&'static str>>>,
        }
        impl NativeLocalLifecycle for Retained {
            fn node(&self) -> Result<NodeId, SharedAgentHostError> {
                unreachable!()
            }
            fn system_attachment(
                &self,
                _: usize,
            ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
                unreachable!()
            }
            fn local_attachment(
                &self,
                _: usize,
            ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
                unreachable!()
            }
            fn create(
                &mut self,
                _: super::super::sdk::AgentDescriptor,
                _: super::super::sdk::authority::AuthorityCredentialCall,
                _: super::super::package_admission::AdmittedRuntimePackage,
            ) -> Result<
                (
                    AgentId,
                    super::super::sdk::authority::ManagementApplicationAck,
                ),
                SharedAgentHostError,
            > {
                unreachable!()
            }
            fn reserve_shared_create(
                &mut self,
                _: &super::super::sdk::AgentDescriptor,
                _: &super::super::sdk::authority::AuthorityCredentialCall,
                _: &super::super::clean_bootstrap::SharedGenesisRuntimePackage,
                _: &super::super::genesis::AgentReplicaCommittee,
            ) -> Result<AgentGenesisLocator, SharedAgentHostError> {
                panic!("retained continuation cannot reach fresh reservation");
            }
            fn retained_shared_create_locator(
                &mut self,
                descriptor: &super::super::sdk::AgentDescriptor,
                call: &super::super::sdk::authority::AuthorityCredentialCall,
                runtime: &super::super::clean_bootstrap::SharedGenesisRuntimePackage,
                replicas: &super::super::genesis::AgentReplicaCommittee,
            ) -> Result<Option<AgentGenesisLocator>, SharedAgentHostError> {
                self.calls.lock().unwrap().push("lookup");
                if descriptor != self.submission.descriptor() {
                    return Ok(None);
                }
                if call != self.submission.call()
                    || runtime.exact_bytes() != self.submission.runtime().exact_bytes()
                    || replicas != self.submission.committee()
                {
                    return Err(SharedAgentHostError::Conflict);
                }
                Ok(Some(AgentGenesisLocator {
                    space: crate::service::SpaceId(descriptor.identity.space.0),
                    agent: crate::service::AgentId(descriptor.identity.agent.0),
                }))
            }
            fn shared_create_archive(
                &mut self,
                _: AgentGenesisLocator,
            ) -> Result<
                Option<super::super::genesis::AgentGenesisArchiveRecord>,
                SharedAgentHostError,
            > {
                Ok(None)
            }
            fn endorse_shared_create(
                &mut self,
                _: AgentGenesisLocator,
            ) -> Result<Vec<super::super::committee::AuthoritySignature>, SharedAgentHostError>
            {
                self.calls.lock().unwrap().push("prepare");
                Err(SharedAgentHostError::CapacityExhausted)
            }
        }
        let (submission, _) = super::super::local_lifecycle::shared_submissions_for_test(false);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let (mut owner, _, _) = held_inventory_owner();
        owner.lifecycle = Some((
            Box::new(Retained {
                submission: submission.clone(),
                calls: calls.clone(),
            }),
            1,
        ));
        owner.accepted_head = Some(head(1));
        owner.routes_verified = true;
        assert!(owner.is_ready());
        let accepted = owner.accepted_head;
        let queue = LocalLifecycleQueue::default();
        queue.open().unwrap();
        let result = queue
            .submit_shared_create(submission.clone(), false)
            .unwrap();
        owner.source = Box::new(FailedInventory(AgentProductionOwnerError::ProjectionBusy));
        assert_eq!(
            owner.reconcile(),
            Err(AgentProductionOwnerError::ProjectionBusy)
        );
        owner.quarantine_routes().unwrap();
        assert!(!owner.is_ready());
        assert!(owner.ingress().is_err());
        let PendingLocalLifecycle::CreateShared {
            submission: queued,
            retained_only,
            reply,
        } = queue.pop().unwrap().unwrap()
        else {
            panic!("wrong lifecycle variant");
        };
        assert!(!retained_only);
        reply
            .try_send(owner.create_shared_disposition(queued, retained_only))
            .unwrap();
        assert_eq!(
            result.recv().unwrap(),
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::CapacityExhausted
            ))
        );
        assert_eq!(*calls.lock().unwrap(), ["lookup", "prepare"]);
        assert_eq!(owner.accepted_head, accepted);
        assert!(!owner.is_ready());
        assert!(owner.ingress().is_err());
        // The generic fresh boundary is unchanged, even for an exact caller.
        let runtime = super::super::clean_bootstrap::SharedGenesisRuntimePackage::External(
            submission.runtime().clone(),
        );
        assert_eq!(
            owner.reserve_shared_create(
                submission.descriptor(),
                submission.call(),
                &runtime,
                submission.committee()
            ),
            Err(AgentProductionOwnerError::InvalidConfiguration)
        );

        // The restriction belongs to the admitted queue item, not the
        // owner's readiness when it eventually executes. Publication may
        // recover between enqueue and dispatch without permitting a fresh
        // reservation through the recovery-only item.
        let exact_bytes = submission.encode();
        let result = queue
            .submit_shared_create(submission.clone(), true)
            .unwrap();
        assert!(!owner.is_ready());
        owner.routes_verified = true;
        assert!(owner.is_ready());
        let PendingLocalLifecycle::CreateShared {
            submission: queued,
            retained_only,
            reply,
        } = queue.pop().unwrap().unwrap()
        else {
            panic!("wrong lifecycle variant");
        };
        assert!(retained_only);
        assert_eq!(queued.encode(), exact_bytes);
        reply
            .try_send(owner.create_shared_disposition(queued, retained_only))
            .unwrap();
        assert_eq!(
            result.recv().unwrap(),
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::CapacityExhausted
            ))
        );
        assert_eq!(
            *calls.lock().unwrap(),
            ["lookup", "prepare", "lookup", "prepare"]
        );
        assert_eq!(submission.encode(), exact_bytes);
        assert_eq!(owner.accepted_head, accepted);
        assert!(owner.is_ready());

        // Owner ordering only: these deliberately changed inputs exercise
        // lookup refusal, not raw-signature or native-binding qualification.
        // Every refusal must stop before preparation and must not fall back
        // to the fresh factory even though the owner is ready again.
        let expected_calls = [
            "lookup", "prepare", "lookup", "prepare", "lookup", "lookup", "lookup", "lookup",
        ];
        let mut absent = submission.descriptor().clone();
        absent.identity.agent = super::super::sdk::AgentId([0xf1; 32]);
        assert_eq!(
            owner.shared_create_locator(
                &absent,
                submission.call(),
                &runtime,
                submission.committee(),
                true,
            ),
            Err(AgentProductionOwnerError::ProjectionNotReady)
        );
        let mut altered_call = submission.call().clone();
        altered_call.requested_expires_at += 1;
        assert_eq!(
            owner.shared_create_locator(
                submission.descriptor(),
                &altered_call,
                &runtime,
                submission.committee(),
                true,
            ),
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::Conflict
            ))
        );
        let altered_runtime =
            super::super::package_admission::tests::admitted_state_fixture_max_actors(
                submission.runtime().program_bytes().to_vec(),
                submission.runtime().manifest().capabilities.max_actors - 1,
            );
        assert_ne!(
            altered_runtime.exact_bytes(),
            submission.runtime().exact_bytes()
        );
        let altered_runtime =
            super::super::clean_bootstrap::SharedGenesisRuntimePackage::External(altered_runtime);
        assert_eq!(
            owner.shared_create_locator(
                submission.descriptor(),
                submission.call(),
                &altered_runtime,
                submission.committee(),
                true,
            ),
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::Conflict
            ))
        );
        let altered_roster = super::super::genesis::AgentReplicaCommittee::new(
            submission.committee().space(),
            submission.committee().agent(),
            submission.committee().profile(),
            submission.committee().members()[..2].to_vec(),
        )
        .unwrap();
        assert_ne!(&altered_roster, submission.committee());
        assert_eq!(
            owner.shared_create_locator(
                submission.descriptor(),
                submission.call(),
                &runtime,
                &altered_roster,
                true,
            ),
            Err(AgentProductionOwnerError::Lifecycle(
                SharedAgentHostError::Conflict
            ))
        );
        assert_eq!(*calls.lock().unwrap(), expected_calls);
        assert_eq!(owner.accepted_head, accepted);
        assert!(owner.is_ready());
        owner.request_shutdown();
        assert_eq!(
            owner.create_shared_disposition(submission, true),
            Err(AgentProductionOwnerError::ShutdownRequested)
        );
        assert_eq!(*calls.lock().unwrap(), expected_calls);
        queue.close();
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    fn queued_exact_shared_install_reuses_retained_continuation_after_busy_quarantine() {
        use super::super::genesis::AgentGenesisLocator;
        use super::super::local_lifecycle::{
            LocalLifecycleQueue, NativeLocalLifecycle, PendingLocalLifecycle,
            SharedInstallSubmission,
        };
        use super::super::shared_host::SharedAgentHostError;

        // Dispatch ordering only. The real controller tests authenticate the
        // durable intent and package; this backend never fabricates a terminal.
        struct Retained {
            submission: SharedInstallSubmission,
            calls: Arc<Mutex<Vec<&'static str>>>,
        }
        impl NativeLocalLifecycle for Retained {
            fn node(&self) -> Result<NodeId, SharedAgentHostError> {
                unreachable!()
            }
            fn system_attachment(
                &self,
                _: usize,
            ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
                unreachable!()
            }
            fn local_attachment(
                &self,
                _: usize,
            ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
                unreachable!()
            }
            fn create(
                &mut self,
                _: super::super::sdk::AgentDescriptor,
                _: super::super::sdk::authority::AuthorityCredentialCall,
                _: super::super::package_admission::AdmittedRuntimePackage,
            ) -> Result<
                (AgentId, super::super::sdk::authority::ManagementApplicationAck),
                SharedAgentHostError,
            > {
                unreachable!()
            }
            fn initialize_shared_management(
                &mut self,
                _: AgentGenesisLocator,
            ) -> Result<(), SharedAgentHostError> {
                panic!("restricted Install cannot initialize management");
            }
            fn prepare_shared_install(
                &mut self,
                _: super::super::sdk::InstallActor,
                _: super::super::sdk::authority::AuthorityCredentialCall,
                _: &super::super::package_admission::AdmittedActorPackage,
            ) -> Result<(), SharedAgentHostError> {
                panic!("restricted Install cannot prepare fresh custody");
            }
            fn retained_shared_install_locator(
                &mut self,
                install: &super::super::sdk::InstallActor,
                call: &super::super::sdk::authority::AuthorityCredentialCall,
                package: &super::super::package_admission::AdmittedActorPackage,
            ) -> Result<Option<AgentGenesisLocator>, SharedAgentHostError> {
                self.calls.lock().unwrap().push("lookup");
                if call.managed.agent != self.submission.call().managed.agent {
                    return Ok(None);
                }
                if install != self.submission.install()
                    || call != self.submission.call()
                    || package.exact_bytes() != self.submission.package().exact_bytes()
                {
                    return Err(SharedAgentHostError::Conflict);
                }
                Ok(Some(AgentGenesisLocator {
                    space: crate::service::SpaceId(call.managed.space.0),
                    agent: crate::service::AgentId(call.managed.agent.0),
                }))
            }
            fn complete_shared_install(
                &mut self,
                _: AgentGenesisLocator,
            ) -> Result<
                super::super::clean_authority_issuer::SignedManagementTerminal,
                SharedAgentHostError,
            > {
                self.calls.lock().unwrap().push("complete");
                Err(SharedAgentHostError::CapacityExhausted)
            }
        }
        let (_, submission) = super::super::local_lifecycle::shared_submissions_for_test(false);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let (mut owner, _, _) = held_inventory_owner();
        owner.lifecycle = Some((
            Box::new(Retained {
                submission: submission.clone(),
                calls: calls.clone(),
            }),
            1,
        ));
        owner.accepted_head = Some(head(1));
        owner.routes_verified = true;
        let accepted = owner.accepted_head;
        let queue = LocalLifecycleQueue::default();
        queue.open().unwrap();
        let result = queue.submit_shared_install(submission.clone(), false).unwrap();
        owner.source = Box::new(FailedInventory(AgentProductionOwnerError::ProjectionBusy));
        assert_eq!(owner.reconcile(), Err(AgentProductionOwnerError::ProjectionBusy));
        owner.quarantine_routes().unwrap();
        assert!(!owner.is_ready());
        let PendingLocalLifecycle::InstallShared { submission: queued, retained_only, reply } =
            queue.pop().unwrap().unwrap()
        else {
            panic!("wrong lifecycle variant");
        };
        assert!(!retained_only);
        reply.try_send(owner.install_shared_disposition(queued, retained_only)).unwrap();
        assert_eq!(result.recv().unwrap(), Err(AgentProductionOwnerError::Lifecycle(
            SharedAgentHostError::CapacityExhausted
        )));
        assert_eq!(*calls.lock().unwrap(), ["lookup", "complete"]);
        assert_eq!(owner.accepted_head, accepted);
        assert!(!owner.is_ready());
        assert!(owner.ingress().is_err());
        assert_eq!(
            owner.prepare_shared_install(submission.install().clone(), submission.call().clone(), submission.package()),
            Err(AgentProductionOwnerError::InvalidConfiguration)
        );

        // Recovery-only enqueue stays restricted when routes become ready
        // before dispatch. Its exact bytes and retained result remain owned.
        let exact_bytes = submission.encode();
        let result = queue.submit_shared_install(submission.clone(), true).unwrap();
        owner.routes_verified = true;
        assert!(owner.is_ready());
        let PendingLocalLifecycle::InstallShared { submission: queued, retained_only, reply } =
            queue.pop().unwrap().unwrap()
        else {
            panic!("wrong lifecycle variant");
        };
        assert!(retained_only);
        assert_eq!(queued.encode(), exact_bytes);
        reply.try_send(owner.install_shared_disposition(queued, retained_only)).unwrap();
        assert_eq!(result.recv().unwrap(), Err(AgentProductionOwnerError::Lifecycle(
            SharedAgentHostError::CapacityExhausted
        )));
        assert_eq!(*calls.lock().unwrap(), ["lookup", "complete", "lookup", "complete"]);

        let mut absent = submission.call().clone();
        absent.managed.agent = super::super::sdk::AgentId([0xf1; 32]);
        assert_eq!(
            owner.shared_install_locator(submission.install(), &absent, submission.package(), true),
            Err(AgentProductionOwnerError::ProjectionNotReady)
        );
        let mut altered_call = submission.call().clone();
        altered_call.requested_expires_at += 1;
        assert_eq!(
            owner.shared_install_locator(submission.install(), &altered_call, submission.package(), true),
            Err(AgentProductionOwnerError::Lifecycle(SharedAgentHostError::Conflict))
        );
        let mut altered_install = submission.install().clone();
        altered_install.registry_reservation = super::super::sdk::Hash([0xf2; 32]);
        assert_eq!(
            owner.shared_install_locator(&altered_install, submission.call(), submission.package(), true),
            Err(AgentProductionOwnerError::Lifecycle(SharedAgentHostError::Conflict))
        );
        assert_eq!(*calls.lock().unwrap(), ["lookup", "complete", "lookup", "complete", "lookup", "lookup", "lookup"]);
        assert_eq!(submission.encode(), exact_bytes);
        assert_eq!(owner.accepted_head, accepted);
        assert!(owner.is_ready());
        owner.request_shutdown();
        assert_eq!(owner.install_shared_disposition(submission, true), Err(AgentProductionOwnerError::ShutdownRequested));
        queue.close();
        owner.shutdown_and_join().unwrap();
    }

    fn check_reconciliation_deadline(lifecycle: bool) {
        use super::super::shared_host::SharedAgentHostError;
        use std::sync::atomic::{AtomicU8, Ordering};
        struct Admission(Arc<AtomicU8>);
        impl super::super::local_lifecycle::NativeLocalLifecycle for Admission {
            fn management_admission_held(&self) -> Result<bool, SharedAgentHostError> {
                match self.0.load(Ordering::Acquire) {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(SharedAgentHostError::Unavailable),
                }
            }
            fn node(&self) -> Result<NodeId, SharedAgentHostError> {
                unreachable!()
            }
            fn system_attachment(
                &self,
                _: usize,
            ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
                unreachable!()
            }
            fn local_attachment(
                &self,
                _: usize,
            ) -> Result<AgentRouteHostAttachment, AgentRouteAdapterError> {
                unreachable!()
            }
            fn create(
                &mut self,
                _: AgentDescriptor,
                _: super::super::sdk::authority::AuthorityCredentialCall,
                _: super::super::package_admission::AdmittedRuntimePackage,
            ) -> Result<
                (
                    AgentId,
                    super::super::sdk::authority::ManagementApplicationAck,
                ),
                SharedAgentHostError,
            > {
                unreachable!()
            }
        }
        let node = NodeId([0x31; 32]);
        let descriptor = descriptor(1, AgentProfile::Shared, node);
        let actor = actor(&descriptor, true);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let interval = Duration::from_secs(60);
        // Model an overdue admission without sleeping or depending on query
        // speed. The old start-based deadline would already be in the past.
        let admitted = Instant::now().checked_sub(interval * 2).unwrap();
        let mut owner = AgentProductionOwner {
            node,
            system_agent: descriptor.identity.agent,
            supervisor: Some(
                AgentSupervisorOwner::start(AgentSupervisorLimits::default()).unwrap(),
            ),
            system: OwnedRouteSlot::Empty,
            local: OwnedRouteSlot::Empty,
            local_by_agent: None,
            shared: OwnedRouteSlot::Empty,
            shared_by_agent: None,
            source: Box::new(client(
                vec![descriptor],
                vec![actor],
                head(1),
                calls.clone(),
            )),
            accepted_head: None,
            routes_verified: false,
            routes_need_quarantine: false,
            reconcile_interval: interval,
            reconcile_after: admitted,
            lifecycle: None,
            completed_local_publication: None,
            completed_local_install: None,
        };
        let before = Instant::now();
        let admission = Arc::new(AtomicU8::new(1));
        owner.lifecycle = Some((Box::new(Admission(admission.clone())), 1));
        for now in [admitted, before, before + interval * 2] {
            assert_eq!(owner.drive_if_due(now), Ok(false));
            assert!(!owner.is_ready());
            assert!(owner.ingress().is_err());
            assert!(calls.lock().unwrap().is_empty());
            assert_eq!(owner.reconcile_after, admitted);
        }
        admission.store(2, Ordering::Release);
        assert!(owner.drive_if_due(before).is_err());
        assert!(calls.lock().unwrap().is_empty());
        admission.store(0, Ordering::Release);
        let completed_install = Some((
            Hash([0x31; 32]),
            head(1),
            AgentRouteIdentity::new(
                AgentRouteKey::new(SpaceId([1; 32]), AgentId([2; 32]), ActorId([3; 32])).unwrap(),
                Hash([7; 32]),
                DeploymentId([4; 32]),
                DeploymentId([5; 32]),
                ProgramId([6; 32]),
                AgentProfile::Local,
            )
            .unwrap(),
        ));
        owner.completed_local_install = completed_install;
        owner.completed_local_publication = Some((super::super::sdk::Hash([0x31; 32]), head(1)));
        if lifecycle {
            assert_eq!(owner.reconcile(), Ok(()));
        } else {
            assert_eq!(owner.drive_if_due(admitted), Ok(true));
        }
        assert!(owner.reconcile_after >= before + interval);
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(owner.is_ready());
        assert_eq!(owner.drive_if_due(before), Ok(false));
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(owner.completed_local_publication.is_none());
        assert!(owner.completed_local_install.is_none());
        owner.completed_local_install = completed_install;
        owner.completed_local_publication = Some((super::super::sdk::Hash([0x31; 32]), head(1)));
        owner.source = Box::new(client(Vec::new(), Vec::new(), head(1), calls));
        assert!(owner.reconcile().is_err());
        assert!(owner.completed_local_publication.is_none());
        assert!(owner.completed_local_install.is_none());
        owner.shutdown_and_join().unwrap();
    }

    #[test]
    fn projection_head_revision_is_total_and_exact_retries_are_stable() {
        let accepted = head(4);
        assert_eq!(accept_head(Some(accepted), accepted), Ok(()));

        let mut historical = accepted;
        historical.state_revision = NonZeroU64::new(3).unwrap();
        historical.state_commitment = Hash([3; 32]);
        assert_eq!(
            accept_head(Some(accepted), historical),
            Err(AgentProductionOwnerError::StaleHead)
        );

        let mut same_revision_conflict = accepted;
        same_revision_conflict.state_commitment = Hash([0x91; 32]);
        assert_eq!(
            accept_head(Some(accepted), same_revision_conflict),
            Err(AgentProductionOwnerError::ConflictingHead)
        );

        let mut impossible_progress = accepted;
        impossible_progress.state_revision = NonZeroU64::new(5).unwrap();
        assert_eq!(
            accept_head(Some(accepted), impossible_progress),
            Err(AgentProductionOwnerError::ConflictingHead)
        );

        let mut acknowledged = accepted;
        acknowledged.state_revision = NonZeroU64::new(5).unwrap();
        acknowledged.state_commitment = Hash([5; 32]);
        assert_eq!(accept_head(Some(accepted), acknowledged), Ok(()));

        let mut counter_rollback = acknowledged;
        counter_rollback.state_revision = NonZeroU64::new(6).unwrap();
        counter_rollback.authorization_sequence = NonZeroU64::new(3).unwrap();
        counter_rollback.state_commitment = Hash([6; 32]);
        assert_eq!(
            accept_head(Some(acknowledged), counter_rollback),
            Err(AgentProductionOwnerError::ConflictingHead)
        );
    }

    #[test]
    fn inventory_accepts_bounded_short_pages_for_agents_replicas_and_actors() {
        let mut descriptors: Vec<_> = (1..=3)
            .map(|index| {
                let mut item = descriptor(index, AgentProfile::Shared, NodeId([0x31; 32]));
                let replica = item.replicas[0].clone();
                item.replicas = (0x31..=0x33)
                    .map(|node| {
                        let mut replica = replica.clone();
                        replica.node = NodeId([node; 32]);
                        replica
                    })
                    .collect();
                item.validate().unwrap();
                item
            })
            .collect();
        descriptors.sort_by_key(|item| item.identity.agent);
        let actors: Vec<_> = descriptors
            .iter()
            .flat_map(|item| {
                (0x41..=0x43).map(move |id| {
                    let mut row = actor(item, false);
                    row.entry.actor = ActorId([id; 32]);
                    row.entry.name = format!("actor-{id}");
                    row
                })
            })
            .collect();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut source = CleanAuthorityProjectionClient::new(
            Box::new(ProjectionTransport {
                target: target(),
                head: head(1),
                actor_head: head(1),
                descriptors: descriptors.clone(),
                actors: actors.clone(),
                calls: calls.clone(),
                page_cap: 1,
            }),
            Box::new(TestAuthenticator { ordinal: 0 }),
        );
        let inventory = source.load_inventory().unwrap();
        assert_eq!(inventory.agents.len(), descriptors.len());
        for (row, expected) in inventory.agents.iter().zip(&descriptors) {
            assert_eq!(row.descriptor(), expected);
            let expected_actors: Vec<_> = actors
                .iter()
                .filter(|actor| actor.agent == expected.identity.agent)
                .cloned()
                .collect();
            assert_eq!(row.actors(), expected_actors);
        }
        assert_eq!(calls.lock().unwrap().len(), 3 * (1 + 3 + 3));
        // An authenticated unchanged-head refresh still reuses the complete
        // inventory only after a new credential query succeeds.
        assert_eq!(source.load_inventory().unwrap(), inventory);
        assert_eq!(calls.lock().unwrap().len(), 22);
    }

    #[test]
    fn inventory_is_exact_same_head_and_bounded_before_physical_mutation() {
        let node = NodeId([0x31; 32]);
        let system_descriptor = descriptor(1, AgentProfile::Shared, node);
        let actor = actor(&system_descriptor, true);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let inventory = client(
            vec![system_descriptor.clone()],
            vec![actor.clone()],
            head(1),
            calls.clone(),
        )
        .load_inventory()
        .unwrap();
        assert_eq!(inventory.agents.len(), 1);
        assert_eq!(inventory.agents[0].descriptor(), &system_descriptor);
        assert_eq!(inventory.agents[0].actors(), &[actor]);
        assert_eq!(calls.lock().unwrap().len(), 1);

        let changed_head_calls = Arc::new(Mutex::new(Vec::new()));
        assert_eq!(
            client(
                vec![system_descriptor],
                vec![],
                head(2),
                changed_head_calls.clone(),
            )
            .load_inventory(),
            Err(AgentProductionOwnerError::InconsistentHead)
        );
        assert_eq!(changed_head_calls.lock().unwrap().len(), 2);

        let mut descriptors = (0..=MAX_INVENTORY_AGENTS as u64)
            .map(|index| descriptor(index + 10, AgentProfile::Shared, node))
            .collect::<Vec<_>>();
        descriptors.sort_by_key(|descriptor| descriptor.identity.agent);
        let bounded_calls = Arc::new(Mutex::new(Vec::new()));
        assert_eq!(
            client(descriptors, Vec::new(), head(1), bounded_calls.clone()).load_inventory(),
            Err(AgentProductionOwnerError::InventoryLimit)
        );
        assert_eq!(
            bounded_calls.lock().unwrap().len(),
            MAX_INVENTORY_AGENTS.div_ceil(MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES) + 1
        );
    }
}
