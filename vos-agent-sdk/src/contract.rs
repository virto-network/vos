//! Signed compatibility contract shared by actor and runtime packages.

use crate::{
    Hash, MAX_CATALOG_ARTIFACT_REFERENCED_BYTES, MAX_CATALOG_ARTIFACT_REFERENCES,
    MAX_RUNTIME_STATE_BYTES, MAX_TRANSITION_PROOF_MATERIAL_BYTES, RUNTIME_ABI_ID,
    RuntimeCapabilities, RuntimeResourceUsage,
};

/// Actor entry ABI emitted by the canonical actor toolchain.
pub const ACTOR_ABI: u32 = 4;

/// Descriptor committed by [`CONTROL_SCHEMA_ID`].
pub const CONTROL_SCHEMA_DESCRIPTOR: &[u8] = &RUNTIME_ABI_ID.0;

/// Canonical management schema. This constant is BLAKE2b-256 over
/// `vos/agent/control-schema` followed by [`CONTROL_SCHEMA_DESCRIPTOR`].
pub const CONTROL_SCHEMA_ID: Hash = Hash([
    0xd4, 0x48, 0xfd, 0xea, 0xd3, 0xdf, 0xcb, 0xf0, 0x9f, 0x9f, 0x54, 0x0e, 0x94, 0xec, 0xe2, 0x9f,
    0xd7, 0x18, 0x2b, 0x49, 0x4d, 0xd5, 0x91, 0xad, 0x79, 0x8d, 0x2a, 0xf9, 0x05, 0x49, 0xaa, 0x01,
]);

/// One actor ABI requirement signed into an actor package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActorPackageContract {
    pub actor_abi: u32,
}

impl ActorPackageContract {
    pub const fn canonical() -> Self {
        Self {
            actor_abi: ACTOR_ABI,
        }
    }

    pub fn is_valid(self) -> bool {
        self.actor_abi != 0
    }
}

/// Inclusive actor ABI interval implemented by one runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActorAbiRange {
    pub minimum: u32,
    pub maximum: u32,
}

impl ActorAbiRange {
    pub const fn exact(actor_abi: u32) -> Self {
        Self {
            minimum: actor_abi,
            maximum: actor_abi,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.minimum != 0 && self.minimum <= self.maximum
    }

    pub const fn supports(self, actor_abi: u32) -> bool {
        self.is_valid() && actor_abi >= self.minimum && actor_abi <= self.maximum
    }
}

/// Runtime-owned state-image and catalog-closure ceilings authenticated by
/// an AgentRuntime package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeResourceLimits {
    pub max_runtime_state_bytes: u32,
    pub max_artifact_references: u32,
    pub max_artifact_referenced_bytes: u64,
    pub max_proof_material_bytes: u64,
}

impl RuntimeResourceLimits {
    pub const fn standard() -> Self {
        Self {
            max_runtime_state_bytes: MAX_RUNTIME_STATE_BYTES as u32,
            max_artifact_references: MAX_CATALOG_ARTIFACT_REFERENCES,
            max_artifact_referenced_bytes: MAX_CATALOG_ARTIFACT_REFERENCED_BYTES,
            max_proof_material_bytes: MAX_TRANSITION_PROOF_MATERIAL_BYTES,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.max_runtime_state_bytes != 0
            && self.max_runtime_state_bytes <= MAX_RUNTIME_STATE_BYTES as u32
            && self.max_artifact_references != 0
            && self.max_artifact_references <= MAX_CATALOG_ARTIFACT_REFERENCES
            && self.max_artifact_referenced_bytes != 0
            && self.max_artifact_referenced_bytes <= MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
            && self.max_proof_material_bytes != 0
            && self.max_proof_material_bytes <= MAX_TRANSITION_PROOF_MATERIAL_BYTES
    }
}

/// Mutable runtime resource policy selected beneath immutable package limits.
///
/// Every mutable ceiling may be narrowed only when the current usage still
/// fits. Immutable package limits remain the signed upper bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeResourcePolicy {
    pub max_actors: u32,
    pub max_runtime_state_bytes: u32,
    pub max_artifact_references: u32,
    pub max_artifact_referenced_bytes: u64,
    pub max_proof_material_bytes: u64,
}

impl RuntimeResourcePolicy {
    pub const fn standard() -> Self {
        Self {
            max_actors: crate::STANDARD_MAX_ACTORS,
            max_runtime_state_bytes: MAX_RUNTIME_STATE_BYTES as u32,
            max_artifact_references: MAX_CATALOG_ARTIFACT_REFERENCES,
            max_artifact_referenced_bytes: MAX_CATALOG_ARTIFACT_REFERENCED_BYTES,
            max_proof_material_bytes: MAX_TRANSITION_PROOF_MATERIAL_BYTES,
        }
    }

    /// Deterministic initial policy for one descriptor's signed runtime
    /// capabilities and immutable resource limits.
    pub const fn initial(capabilities: RuntimeCapabilities, limits: RuntimeResourceLimits) -> Self {
        Self {
            max_actors: capabilities.max_actors,
            max_runtime_state_bytes: limits.max_runtime_state_bytes,
            max_artifact_references: limits.max_artifact_references,
            max_artifact_referenced_bytes: limits.max_artifact_referenced_bytes,
            max_proof_material_bytes: limits.max_proof_material_bytes,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.max_actors != 0
            && self.max_actors <= crate::STANDARD_MAX_ACTORS
            && self.max_runtime_state_bytes != 0
            && self.max_runtime_state_bytes <= MAX_RUNTIME_STATE_BYTES as u32
            && self.max_artifact_references != 0
            && self.max_artifact_references <= MAX_CATALOG_ARTIFACT_REFERENCES
            && self.max_artifact_referenced_bytes != 0
            && self.max_artifact_referenced_bytes <= MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
            && self.max_proof_material_bytes != 0
            && self.max_proof_material_bytes <= MAX_TRANSITION_PROOF_MATERIAL_BYTES
    }

    pub const fn is_within(
        self,
        capabilities: RuntimeCapabilities,
        limits: RuntimeResourceLimits,
    ) -> bool {
        self.is_valid()
            && capabilities.max_actors != 0
            && self.max_actors <= capabilities.max_actors
            && limits.is_valid()
            && self.max_runtime_state_bytes <= limits.max_runtime_state_bytes
            && self.max_artifact_references <= limits.max_artifact_references
            && self.max_artifact_referenced_bytes <= limits.max_artifact_referenced_bytes
            && self.max_proof_material_bytes <= limits.max_proof_material_bytes
    }

    pub const fn admits_usage(self, usage: RuntimeResourceUsage) -> bool {
        self.is_valid()
            && usage.actors <= self.max_actors
            && usage.state_bytes <= self.max_runtime_state_bytes
            && usage.artifact_references <= self.max_artifact_references
            && usage.artifact_referenced_bytes <= self.max_artifact_referenced_bytes
            && usage.proof_material_bytes <= self.max_proof_material_bytes
    }
}

/// Durable state migration behavior implemented by a runtime package.
/// Unknown values are rejected by the canonical decoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RuntimeMigrationPolicy {
    None = 0,
}

/// Complete mandatory contract signed into an AgentRuntime package.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimePackageContract {
    pub lifecycle_abi: Hash,
    pub actor_abis: ActorAbiRange,
    pub control_schema: Hash,
    pub resources: RuntimeResourceLimits,
    pub migration: RuntimeMigrationPolicy,
}

impl RuntimePackageContract {
    pub const fn canonical() -> Self {
        Self {
            lifecycle_abi: RUNTIME_ABI_ID,
            actor_abis: ActorAbiRange::exact(ACTOR_ABI),
            control_schema: CONTROL_SCHEMA_ID,
            resources: RuntimeResourceLimits::standard(),
            migration: RuntimeMigrationPolicy::None,
        }
    }

    pub fn is_valid(self) -> bool {
        self.lifecycle_abi.0 == RUNTIME_ABI_ID.0
            && self.actor_abis.is_valid()
            && self.control_schema.0 == CONTROL_SCHEMA_ID.0
            && self.resources.is_valid()
            && matches!(self.migration, RuntimeMigrationPolicy::None)
    }

    pub fn supports(self, actor: ActorPackageContract) -> bool {
        self.is_valid() && actor.is_valid() && self.actor_abis.supports(actor.actor_abi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_abi_interval_is_inclusive_and_fail_closed() {
        let range = ActorAbiRange {
            minimum: 2,
            maximum: 4,
        };
        assert!(!range.supports(1));
        assert!(range.supports(2));
        assert!(range.supports(4));
        assert!(!range.supports(5));
        assert!(
            !ActorAbiRange {
                minimum: 4,
                maximum: 2
            }
            .is_valid()
        );
    }

    #[test]
    fn canonical_runtime_contract_is_explicit_and_bounded() {
        let contract = RuntimePackageContract::canonical();
        assert!(contract.is_valid());
        assert!(contract.supports(ActorPackageContract::canonical()));
        assert_eq!(crate::STANDARD_MAX_ACTORS, 4_096);
        assert_eq!(contract.resources.max_runtime_state_bytes, 4 * 1024 * 1024);
        assert_eq!(
            contract.resources.max_proof_material_bytes,
            64 * 1024 * 1024
        );
        let policy = RuntimeResourcePolicy::initial(
            crate::RuntimeCapabilities::standard(),
            contract.resources,
        );
        assert_eq!(policy, RuntimeResourcePolicy::standard());
        assert!(policy.is_within(crate::RuntimeCapabilities::standard(), contract.resources));
        assert!(policy.admits_usage(crate::RuntimeResourceUsage::default()));
    }

    #[test]
    fn runtime_resource_limits_cover_every_signed_ceiling() {
        let canonical = RuntimeResourceLimits::standard();
        assert!(canonical.is_valid());
        for invalid in [
            RuntimeResourceLimits {
                max_runtime_state_bytes: 0,
                ..canonical
            },
            RuntimeResourceLimits {
                max_runtime_state_bytes: MAX_RUNTIME_STATE_BYTES as u32 + 1,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_references: 0,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_references: MAX_CATALOG_ARTIFACT_REFERENCES + 1,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_referenced_bytes: 0,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_referenced_bytes: MAX_CATALOG_ARTIFACT_REFERENCED_BYTES + 1,
                ..canonical
            },
            RuntimeResourceLimits {
                max_proof_material_bytes: 0,
                ..canonical
            },
            RuntimeResourceLimits {
                max_proof_material_bytes: MAX_TRANSITION_PROOF_MATERIAL_BYTES + 1,
                ..canonical
            },
        ] {
            assert!(!invalid.is_valid());
        }
    }

    #[test]
    fn rrp1_covers_all_mutable_ceilings_and_current_usage() {
        let standard = RuntimeResourcePolicy::standard();
        let limits = RuntimeResourceLimits::standard();
        let capabilities = RuntimeCapabilities::standard();
        assert_eq!(standard.max_actors, 4_096);
        assert_eq!(
            RuntimeResourcePolicy::initial(capabilities, limits),
            standard
        );
        assert!(standard.is_within(capabilities, limits));

        for invalid in [
            RuntimeResourcePolicy {
                max_actors: 0,
                ..standard
            },
            RuntimeResourcePolicy {
                max_actors: crate::STANDARD_MAX_ACTORS + 1,
                ..standard
            },
            RuntimeResourcePolicy {
                max_runtime_state_bytes: 0,
                ..standard
            },
            RuntimeResourcePolicy {
                max_runtime_state_bytes: MAX_RUNTIME_STATE_BYTES as u32 + 1,
                ..standard
            },
            RuntimeResourcePolicy {
                max_artifact_references: 0,
                ..standard
            },
            RuntimeResourcePolicy {
                max_artifact_references: MAX_CATALOG_ARTIFACT_REFERENCES + 1,
                ..standard
            },
            RuntimeResourcePolicy {
                max_artifact_referenced_bytes: 0,
                ..standard
            },
            RuntimeResourcePolicy {
                max_artifact_referenced_bytes: MAX_CATALOG_ARTIFACT_REFERENCED_BYTES + 1,
                ..standard
            },
            RuntimeResourcePolicy {
                max_proof_material_bytes: 0,
                ..standard
            },
            RuntimeResourcePolicy {
                max_proof_material_bytes: MAX_TRANSITION_PROOF_MATERIAL_BYTES + 1,
                ..standard
            },
        ] {
            assert!(!invalid.is_valid());
        }

        let narrowed_limits = RuntimeResourceLimits {
            max_runtime_state_bytes: 10,
            max_artifact_references: 11,
            max_artifact_referenced_bytes: 12,
            max_proof_material_bytes: 13,
        };
        let narrowed_capabilities = RuntimeCapabilities {
            max_actors: 9,
            ..capabilities
        };
        let narrowed = RuntimeResourcePolicy::initial(narrowed_capabilities, narrowed_limits);
        assert!(narrowed.is_within(narrowed_capabilities, narrowed_limits));
        assert!(!standard.is_within(narrowed_capabilities, narrowed_limits));

        let usage = RuntimeResourceUsage {
            actors: narrowed.max_actors,
            state_bytes: narrowed.max_runtime_state_bytes,
            artifact_references: narrowed.max_artifact_references,
            artifact_referenced_bytes: narrowed.max_artifact_referenced_bytes,
            proof_material_bytes: narrowed.max_proof_material_bytes,
            ..RuntimeResourceUsage::default()
        };
        assert!(narrowed.admits_usage(usage));
        for over in [
            RuntimeResourceUsage {
                actors: usage.actors + 1,
                ..usage
            },
            RuntimeResourceUsage {
                state_bytes: usage.state_bytes + 1,
                ..usage
            },
            RuntimeResourceUsage {
                artifact_references: usage.artifact_references + 1,
                ..usage
            },
            RuntimeResourceUsage {
                artifact_referenced_bytes: usage.artifact_referenced_bytes + 1,
                ..usage
            },
            RuntimeResourceUsage {
                proof_material_bytes: usage.proof_material_bytes + 1,
                ..usage
            },
        ] {
            assert!(!narrowed.admits_usage(over));
        }
    }

    #[test]
    fn control_schema_pin_matches_descriptor() {
        assert_eq!(
            Hash::digest(b"vos/agent/control-schema", &[CONTROL_SCHEMA_DESCRIPTOR]).0,
            CONTROL_SCHEMA_ID.0
        );
    }
}
