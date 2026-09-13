//! Node-owned production reconciliation for authenticated clean Agent routes.
//!
//! The installed system authority is the only managed inventory source. Its
//! own protected install is independently root-pinned by the system bootstrap
//! owner and checked during the physical route audit. Every bounded
//! page is response-bound to a fresh authenticated query and the same durable
//! authority head is assembled completely before a physical host or supervisor
//! publication is touched.

use core::fmt;
use std::time::{Duration, Instant};

use super::sdk::authority::{
    AuthorityActorProjection, AuthorityActorProjectionPage, AuthorityActorTarget,
    AuthorityAgentProjection, AuthorityAgentProjectionPage, AuthorityAgentReplicaProjectionPage,
    AuthorityCredentialKind, AuthorityCredentialProjection, AuthorityCredentialStatus,
    AuthorityProjectionHead, AuthorityProjectionQuery, AuthorityProjectionSelector,
    MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES, MAX_AUTHORITY_REPLICA_PAGE_ENTRIES,
};
use super::sdk::wire::CanonicalWire;
use super::sdk::{AgentDescriptor, AgentId, AgentProfile, NodeId, PrincipalId};
use super::supervisor::{
    AgentRouteIdentity, AgentRoutePublication, AgentSupervisorError, AgentSupervisorHandle,
    AgentSupervisorLimits, AgentSupervisorOwner,
};
use super::supervisor_adapters::{
    AgentAuthorityRouteProjection, AgentRouteAdapterError, AgentRouteHostAttachment,
    AgentRouteHostHandle,
};

const MAX_INVENTORY_AGENTS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentProductionOwnerError {
    InvalidConfiguration,
    Authentication,
    ProjectionTransport,
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

    fn recover_pending(&mut self) -> Result<bool, AgentProductionOwnerError> {
        Ok(false)
    }

    fn dispatch(
        &mut self,
        query: AuthorityProjectionQuery,
    ) -> Result<Vec<u8>, AgentProductionOwnerError>;
}

struct SystemAgentProjectionTransport {
    target: AuthorityActorTarget,
    handle: AgentRouteHostHandle,
}

impl AuthorityProjectionTransport for SystemAgentProjectionTransport {
    fn target(&self) -> AuthorityActorTarget {
        self.target
    }

    fn recover_pending(&mut self) -> Result<bool, AgentProductionOwnerError> {
        self.handle
            .recover_authority_projection()
            .map_err(|_| AgentProductionOwnerError::ProjectionTransport)
    }

    fn dispatch(
        &mut self,
        query: AuthorityProjectionQuery,
    ) -> Result<Vec<u8>, AgentProductionOwnerError> {
        if query.authority != self.target || query.validate_shape().is_err() {
            return Err(AgentProductionOwnerError::Authentication);
        }
        self.handle
            .authority_projection(query)
            .map_err(|_| AgentProductionOwnerError::ProjectionTransport)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AgentAuthorityInventory {
    head: AuthorityProjectionHead,
    principal: PrincipalId,
    agents: Vec<AgentAuthorityRouteProjection>,
}

trait AuthorityInventorySource: Send {
    fn load_inventory(&mut self) -> Result<AgentAuthorityInventory, AgentProductionOwnerError>;
}

struct CleanAuthorityProjectionClient {
    transport: Box<dyn AuthorityProjectionTransport>,
    authenticator: Box<dyn AuthorityProjectionQueryAuthenticator>,
}

impl CleanAuthorityProjectionClient {
    fn new(
        transport: Box<dyn AuthorityProjectionTransport>,
        authenticator: Box<dyn AuthorityProjectionQueryAuthenticator>,
    ) -> Self {
        Self {
            transport,
            authenticator,
        }
    }

    fn query<T: CanonicalWire + PartialEq>(
        &mut self,
        selector: AuthorityProjectionSelector,
    ) -> Result<(AuthorityProjectionQuery, T), AgentProductionOwnerError> {
        self.transport.recover_pending()?;
        let query = self
            .authenticator
            .authenticate(self.transport.target(), selector)?;
        if query.authority != self.transport.target()
            || query.selector != selector
            || query.validate_shape().is_err()
        {
            return Err(AgentProductionOwnerError::Authentication);
        }
        let bytes = self.transport.dispatch(query.clone())?;
        let response =
            T::decode(&bytes).map_err(|_| AgentProductionOwnerError::InvalidProjection)?;
        if response.encode().ok().as_deref() != Some(bytes.as_slice()) {
            return Err(AgentProductionOwnerError::InvalidProjection);
        }
        Ok((query, response))
    }

    fn load_replicas(
        &mut self,
        agent: &AuthorityAgentProjection,
        head: AuthorityProjectionHead,
    ) -> Result<Vec<super::sdk::AgentReplica>, AgentProductionOwnerError> {
        let limit = u16::try_from(MAX_AUTHORITY_REPLICA_PAGE_ENTRIES)
            .map_err(|_| AgentProductionOwnerError::InventoryLimit)?;
        let maximum_pages = usize::from(agent.replica_count)
            .div_ceil(MAX_AUTHORITY_REPLICA_PAGE_ENTRIES)
            .saturating_add(1);
        let mut entries = Vec::new();
        let mut after = None;
        for _ in 0..maximum_pages {
            let selector = AuthorityProjectionSelector::AgentReplicas {
                agent: agent.identity.agent,
                after,
                limit,
            };
            let (query, page): (_, AuthorityAgentReplicaProjectionPage) = self.query(selector)?;
            if page.query != query
                || page.validate_shape().is_err()
                || !page.matches_agent_at_head(agent, head)
                || entries
                    .len()
                    .checked_add(page.entries.len())
                    .is_none_or(|count| count > usize::from(agent.replica_count))
                || page.next.is_some() && page.entries.len() != usize::from(limit)
            {
                return Err(AgentProductionOwnerError::InconsistentHead);
            }
            entries.extend(page.entries);
            match page.next {
                None if entries.len() == usize::from(agent.replica_count) => return Ok(entries),
                None => return Err(AgentProductionOwnerError::InvalidProjection),
                Some(next) if after != Some(next) => after = Some(next),
                Some(_) => return Err(AgentProductionOwnerError::InvalidProjection),
            }
        }
        Err(AgentProductionOwnerError::InventoryLimit)
    }

    fn load_actors(
        &mut self,
        descriptor: &AgentDescriptor,
        head: AuthorityProjectionHead,
    ) -> Result<Vec<AuthorityActorProjection>, AgentProductionOwnerError> {
        let limit = u16::try_from(MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES)
            .map_err(|_| AgentProductionOwnerError::InventoryLimit)?;
        let maximum = descriptor.capabilities.max_actors as usize;
        let maximum_pages = maximum
            .div_ceil(MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES)
            .saturating_add(1);
        let mut entries = Vec::new();
        let mut after = None;
        for _ in 0..maximum_pages {
            let selector = AuthorityProjectionSelector::Actors {
                agent: descriptor.identity.agent,
                after,
                limit,
            };
            let (query, page): (_, AuthorityActorProjectionPage) = self.query(selector)?;
            if page.query != query
                || page.validate_shape().is_err()
                || page.head != head
                || entries
                    .len()
                    .checked_add(page.entries.len())
                    .is_none_or(|count| count > maximum)
                || page.next.is_some() && page.entries.len() != usize::from(limit)
            {
                return Err(AgentProductionOwnerError::InconsistentHead);
            }
            entries.extend(page.entries);
            match page.next {
                None => return Ok(entries),
                Some(next) if after != Some(next) => after = Some(next),
                Some(_) => return Err(AgentProductionOwnerError::InvalidProjection),
            }
        }
        Err(AgentProductionOwnerError::InventoryLimit)
    }
}

impl AuthorityInventorySource for CleanAuthorityProjectionClient {
    fn load_inventory(&mut self) -> Result<AgentAuthorityInventory, AgentProductionOwnerError> {
        let (credential_query, credential): (_, AuthorityCredentialProjection) =
            self.query(AuthorityProjectionSelector::Credential)?;
        if credential.query != credential_query || credential.validate_shape().is_err() {
            return Err(AgentProductionOwnerError::InvalidProjection);
        }
        if credential.status != AuthorityCredentialStatus::Active {
            return Err(AgentProductionOwnerError::RevokedCredential);
        }
        if credential.kind != self.authenticator.expected_kind() {
            return Err(AgentProductionOwnerError::WrongCredentialKind);
        }
        let head = credential.head;
        let limit = u16::try_from(MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES)
            .map_err(|_| AgentProductionOwnerError::InventoryLimit)?;
        let maximum_pages = MAX_INVENTORY_AGENTS
            .div_ceil(MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES)
            .saturating_add(1);
        let mut rows = Vec::new();
        let mut after = None;
        let mut complete = false;
        for _ in 0..maximum_pages {
            let selector = AuthorityProjectionSelector::Agents { after, limit };
            let (query, page): (_, AuthorityAgentProjectionPage) = self.query(selector)?;
            if page.query != query
                || page.validate_shape().is_err()
                || page.head != head
                || rows
                    .len()
                    .checked_add(page.entries.len())
                    .is_none_or(|count| count > MAX_INVENTORY_AGENTS)
                || page.next.is_some() && page.entries.len() != usize::from(limit)
            {
                return Err(AgentProductionOwnerError::InconsistentHead);
            }
            rows.extend(page.entries);
            match page.next {
                None => {
                    complete = true;
                    break;
                }
                Some(next) if after != Some(next) => after = Some(next),
                Some(_) => return Err(AgentProductionOwnerError::InvalidProjection),
            }
        }
        if !complete {
            return Err(AgentProductionOwnerError::InventoryLimit);
        }

        let mut agents = Vec::with_capacity(rows.len());
        for row in rows {
            let replicas = self.load_replicas(&row, head)?;
            let descriptor = row
                .reconstruct_descriptor(replicas)
                .map_err(|_| AgentProductionOwnerError::InvalidProjection)?;
            let actors = self.load_actors(&descriptor, head)?;
            agents.push(
                AgentAuthorityRouteProjection::new(row.replica_generation, descriptor, actors)
                    .map_err(|_| AgentProductionOwnerError::InvalidProjection)?,
            );
        }
        Ok(AgentAuthorityInventory {
            head,
            principal: credential.principal,
            agents,
        })
    }
}

#[cfg(all(test, feature = "storage", feature = "network", target_os = "linux"))]
pub(crate) fn load_system_inventory_for_test(
    attachment: &AgentRouteHostAttachment,
    authenticator: Box<dyn AuthorityProjectionQueryAuthenticator>,
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
    let inventory = CleanAuthorityProjectionClient::new(
        Box::new(SystemAgentProjectionTransport { target, handle }),
        authenticator,
    )
    .load_inventory()?;
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
    shared: OwnedRouteSlot,
    source: Box<dyn AuthorityInventorySource>,
    accepted_head: Option<AuthorityProjectionHead>,
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
        let authority = match &self.system {
            OwnedRouteSlot::Published { handle, .. } => handle.clone(),
            _ => return Err(AgentProductionOwnerError::InvalidConfiguration),
        };
        Ok(CleanAgentIngress {
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
            shared: OwnedRouteSlot::Empty,
            source: Box::new(source),
            accepted_head: None,
            reconcile_interval,
            reconcile_after: Instant::now(),
            lifecycle,
        };
        if let Some((lifecycle, capacity)) = &owner.lifecycle {
            owner.local = OwnedRouteSlot::Pending(lifecycle.local_attachment(*capacity)?);
        }
        if let Err(error) = owner.reconcile() {
            let _ = owner.shutdown_and_join();
            return Err(error);
        }
        owner.reconcile_after = Instant::now()
            .checked_add(reconcile_interval)
            .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
        Ok(owner)
    }

    pub(crate) fn handle(&self) -> AgentSupervisorHandle {
        self.supervisor
            .as_ref()
            .expect("production owner retains supervisor until consumed")
            .handle()
    }

    pub(crate) fn create_local_agent(
        &mut self,
        descriptor: super::sdk::AgentDescriptor,
        call: super::sdk::authority::AuthorityCredentialCall,
        runtime: super::package_admission::AdmittedRuntimePackage,
    ) -> Result<(AgentId, super::sdk::authority::ManagementApplicationAck), AgentProductionOwnerError>
    {
        if !self.is_running() {
            return Err(AgentProductionOwnerError::InvalidConfiguration);
        }
        let (lifecycle, capacity) = self
            .lifecycle
            .as_mut()
            .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
        let result = lifecycle
            .create(descriptor, call, runtime)
            .map_err(AgentProductionOwnerError::Lifecycle)?;
        if self.local.is_empty() {
            self.local = OwnedRouteSlot::Pending(lifecycle.local_attachment(*capacity)?);
        }
        // The controller released both host locks before route reconciliation.
        // Errors leave durable application evidence for an exact retry.
        self.reconcile()?;
        Ok(result)
    }

    pub(crate) fn is_running(&self) -> bool {
        self.supervisor
            .as_ref()
            .is_some_and(|supervisor| supervisor.handle().is_running())
    }

    pub(crate) fn install_local_host(
        &mut self,
        attachment: AgentRouteHostAttachment,
    ) -> Result<(), AgentProductionOwnerError> {
        install_pending(&mut self.local, attachment)
    }

    pub(crate) fn install_shared_host(
        &mut self,
        attachment: AgentRouteHostAttachment,
    ) -> Result<(), AgentProductionOwnerError> {
        install_pending(&mut self.shared, attachment)
    }

    pub(crate) fn drive_if_due(&mut self, now: Instant) -> Result<bool, AgentProductionOwnerError> {
        if now < self.reconcile_after {
            return Ok(false);
        }
        self.reconcile()?;
        // Physical inventory queries may take longer than the interval. Start
        // the next interval after completion, not at this run's admission, so
        // an overrun cannot keep the node in back-to-back reconciliation.
        self.reconcile_after = Instant::now()
            .max(now)
            .checked_add(self.reconcile_interval)
            .ok_or(AgentProductionOwnerError::InvalidConfiguration)?;
        Ok(true)
    }

    /// Reconciliation is crate-private: only the node owner may mutate route
    /// publication after construction.
    pub(crate) fn reconcile(&mut self) -> Result<(), AgentProductionOwnerError> {
        let inventory = self.source.load_inventory()?;
        accept_head(self.accepted_head, inventory.head)?;
        validate_root_provenance(&inventory, self.system_agent)?;
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
        reconcile_slot(supervisor, &mut self.local, inventory.head, local)?;
        reconcile_slot(supervisor, &mut self.shared, inventory.head, shared)?;
        self.accepted_head = Some(inventory.head);
        Ok(())
    }

    pub(crate) fn request_shutdown(&self) {
        if let Some(supervisor) = self.supervisor.as_ref() {
            supervisor.request_shutdown();
        }
        for slot in [&self.system, &self.local, &self.shared] {
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
        for slot in [&mut self.system, &mut self.local, &mut self.shared] {
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
mod tests {
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

    struct ProjectionTransport {
        target: AuthorityActorTarget,
        head: AuthorityProjectionHead,
        actor_head: AuthorityProjectionHead,
        descriptors: Vec<AgentDescriptor>,
        actors: Vec<AuthorityActorProjection>,
        calls: Arc<Mutex<Vec<AuthorityProjectionSelector>>>,
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
            let bytes = match query.selector {
                AuthorityProjectionSelector::Credential => AuthorityCredentialProjection {
                    query,
                    head: self.head,
                    principal: PrincipalId([0xb1; 32]),
                    status: AuthorityCredentialStatus::Active,
                    kind: AuthorityCredentialKind::Api,
                    builtin_role: AuthorityBuiltinRole::Admin,
                    management_request_high_water: 0,
                    operation_request_high_water: 0,
                    admin_request_high_water: 0,
                    space_roles: Vec::new(),
                    actor_roles: Vec::new(),
                    capabilities: Vec::new(),
                }
                .encode(),
                AuthorityProjectionSelector::Agents { after, limit } => {
                    let entries = self
                        .descriptors
                        .iter()
                        .filter(|descriptor| {
                            after.is_none_or(|after| descriptor.identity.agent > after)
                        })
                        .take(usize::from(limit))
                        .map(|descriptor| AuthorityAgentProjection {
                            identity: descriptor.identity.clone(),
                            creation_nonce: descriptor.creation_nonce,
                            authority: descriptor.authority,
                            private_recovery: descriptor.private_recovery,
                            runtime_package: descriptor.runtime_package.clone(),
                            runtime_contract: descriptor.runtime_contract,
                            capabilities: descriptor.capabilities,
                            replica_count: descriptor.replicas.len() as u16,
                            replica_generation: descriptor.replica_generation(),
                        })
                        .collect::<Vec<_>>();
                    let more = entries.last().is_some_and(|last| {
                        self.descriptors
                            .iter()
                            .any(|descriptor| descriptor.identity.agent > last.identity.agent)
                    });
                    let next = more.then(|| {
                        entries
                            .last()
                            .expect("continued page is nonempty")
                            .identity
                            .agent
                    });
                    AuthorityAgentProjectionPage {
                        query,
                        head: self.head,
                        entries,
                        next,
                    }
                    .encode()
                }
                AuthorityProjectionSelector::AgentReplicas { agent, .. } => {
                    let descriptor = self
                        .descriptors
                        .iter()
                        .find(|descriptor| descriptor.identity.agent == agent)
                        .unwrap();
                    AuthorityAgentReplicaProjectionPage {
                        query,
                        head: self.head,
                        replica_count: descriptor.replicas.len() as u16,
                        replica_generation: descriptor.replica_generation(),
                        entries: descriptor.replicas.clone(),
                        next: None,
                    }
                    .encode()
                }
                AuthorityProjectionSelector::Actors { agent, .. } => AuthorityActorProjectionPage {
                    query,
                    head: self.actor_head,
                    entries: self
                        .actors
                        .iter()
                        .filter(|actor| actor.agent == agent)
                        .cloned()
                        .collect(),
                    next: None,
                }
                .encode(),
            };
            bytes.map_err(|_| AgentProductionOwnerError::InvalidProjection)
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

    #[test]
    fn reconciliation_overrun_waits_a_full_interval_before_running_again() {
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
            shared: OwnedRouteSlot::Empty,
            source: Box::new(client(
                vec![descriptor],
                vec![actor],
                head(1),
                calls.clone(),
            )),
            accepted_head: None,
            reconcile_interval: interval,
            reconcile_after: admitted,
            lifecycle: None,
        };
        let before = Instant::now();
        assert_eq!(owner.drive_if_due(admitted), Ok(true));
        assert!(owner.reconcile_after >= before + interval);
        assert_eq!(calls.lock().unwrap().len(), 4);
        assert_eq!(owner.drive_if_due(before), Ok(false));
        assert_eq!(calls.lock().unwrap().len(), 4);
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
        assert_eq!(calls.lock().unwrap().len(), 4);

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
        assert_eq!(changed_head_calls.lock().unwrap().len(), 4);

        let mut descriptors = (0..=MAX_INVENTORY_AGENTS as u64)
            .map(|index| descriptor(index + 10, AgentProfile::Shared, node))
            .collect::<Vec<_>>();
        descriptors.sort_by_key(|descriptor| descriptor.identity.agent);
        let bounded_calls = Arc::new(Mutex::new(Vec::new()));
        assert_eq!(
            client(descriptors, Vec::new(), head(1), bounded_calls.clone()).load_inventory(),
            Err(AgentProductionOwnerError::InconsistentHead)
        );
        assert_eq!(
            bounded_calls.lock().unwrap().len(),
            1 + MAX_INVENTORY_AGENTS.div_ceil(MAX_AUTHORITY_PROJECTION_PAGE_ENTRIES) + 1
        );
    }
}
