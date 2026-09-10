//! Host-private physical inputs for clean invocation preparation.
//!
//! These values never cross an ingress or authority boundary directly. A
//! Local or Shared physical owner constructs them only after authenticating
//! its live runtime image, actor directory, and catalog namespace. The clean
//! supervisor adapter then seals them into the public prepared invocation.

use super::sdk::contract::ActorPackageContract;
use super::sdk::{
    ActorDirectoryRecord, ActorId, AgentDescriptor, AgentId, Hash, InstallationId, ProducerId,
    RuntimeBlob, RuntimeRequirements,
};

/// Immutable system-bootstrap lineage. Mutable actor entry and package facts
/// are audited independently against the current physical image, so a valid
/// root actor upgrade does not erase its provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhysicalRootLineage {
    pub(crate) agent: AgentId,
    pub(crate) actor: ActorId,
    pub(crate) installation_id: InstallationId,
    pub(crate) registry_reservation: Hash,
    pub(crate) install_request: Hash,
}

impl PhysicalRootLineage {
    pub(crate) fn matches(&self, actor: &super::sdk::authority::AuthorityActorProjection) -> bool {
        actor.agent == self.agent
            && actor.entry.actor == self.actor
            && actor.installation_id == self.installation_id
            && actor.registry_reservation == self.registry_reservation
            && actor.install_request == self.install_request
    }
}

/// Exact physical material selected from one live Agent generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PhysicalInvocationMaterial {
    pub(crate) descriptor: AgentDescriptor,
    pub(crate) actor: ActorDirectoryRecord,
    /// Exact immutable install request retained by the authenticated runtime
    /// image. This is deliberately separate from the mutable actor deployment.
    pub(crate) install_request: Hash,
    /// Package-signature and compatibility facts recovered from the admitted
    /// content-addressed actor package, never from an authority projection.
    pub(crate) producer: ProducerId,
    pub(crate) contract: ActorPackageContract,
    pub(crate) requirements: RuntimeRequirements,
    /// Root provenance is false for ordinary Local/Shared material. The
    /// bootstrapped system owner sets it only after matching the exact retained
    /// root installation from its independently authenticated bootstrap plan.
    pub(crate) root_provenance: bool,
    pub(crate) observed_slot: u64,
    pub(crate) program: RuntimeBlob,
    pub(crate) schema: RuntimeBlob,
    pub(crate) policies: RuntimeBlob,
    pub(crate) installation_data: Option<RuntimeBlob>,
}
