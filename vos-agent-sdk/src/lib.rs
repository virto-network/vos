//! Portable programming and runtime ABI for VOS agents.
//!
//! The SDK depends only on [`vos_protocol`] and is suitable for standard-PVM
//! runtimes and actors compiled with `#![no_std]` plus `alloc`. Host policy,
//! storage engines, networking, and VOS process types are intentionally absent.

#![no_std]

extern crate alloc;

pub mod authority;
pub mod authority_operation;
pub mod catalog;
pub mod contract;
pub mod introspection;
pub mod method_policy;
mod model;
pub mod package;
pub mod private;
pub mod proof;
pub mod proof_system;
mod runtime;
pub mod scheduling;
pub mod schema;
pub mod task;
pub mod wire;

pub use model::*;
pub use proof_system::*;
pub use runtime::*;
pub use task::*;
pub use vos_protocol as protocol;
pub use vos_protocol::{
    ActorId, AgentId, BlobRef, CallId, CapabilityId, ChangeId, CredentialId, DeploymentId, Hash,
    InstallationId, InvocationId, NodeId, OperationId, PrincipalId, ProducerId, ProgramId, RoleId,
    ScheduleId, SpaceId,
};

/// Stable clean-generation management/runtime ABI identity.
pub const RUNTIME_ABI_ID: Hash = Hash(*b"vos-agent-runtime-abi-260911-r15");

/// Maximum bytes named by one content-addressed artifact reference.
pub const MAX_CATALOG_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum canonical constructor-argument bytes admitted for one actor
/// installation. This object is replay input, not mutable actor state;
/// `#[state(const)]` fields are reconstructed by the constructor.
pub const MAX_INSTALLATION_DATA_BYTES: usize = 64 * 1024;
/// Maximum actor records supported by the standard runtime policy.
pub const STANDARD_MAX_ACTORS: u32 = 4_096;
/// One runtime package plus package/schema/policy/constructor arguments for
/// every actor. The optional argument object is included in the signed ceiling.
pub const MAX_CATALOG_ARTIFACT_REFERENCES: u32 = 1 + 4 * STANDARD_MAX_ACTORS;
/// Maximum aggregate bytes in one authenticated package closure.
pub const MAX_CATALOG_ARTIFACT_REFERENCED_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum opaque runtime image accepted by the canonical ABI.
pub const MAX_RUNTIME_STATE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum aggregate canonical nested transition-proof material retained or
/// supplied for one runtime. Signed package limits and mutable RRP1 policy may
/// narrow this ceiling.
pub const MAX_TRANSITION_PROOF_MATERIAL_BYTES: u64 = 64 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_surface_remains_no_std_with_allocated_model_types() {
        let page = ActorDirectoryPage {
            entries: alloc::vec::Vec::new(),
            next: None,
        };
        assert!(page.validate().is_ok());
        assert_eq!(core::mem::size_of::<AgentId>(), 32);
    }
}
