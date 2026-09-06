//! Signed compatibility contract shared by actor and runtime packages.

use crate::{
    Hash, MAX_CATALOG_ARTIFACT_REFERENCED_BYTES, MAX_CATALOG_ARTIFACT_REFERENCES,
    MAX_RUNTIME_STATE_BYTES, RUNTIME_ABI_ID,
};

/// Actor entry ABI emitted by the canonical actor toolchain.
pub const ACTOR_ABI: u32 = 4;

/// Descriptor committed by [`CONTROL_SCHEMA_ID`].
pub const CONTROL_SCHEMA_DESCRIPTOR: &[u8] = &RUNTIME_ABI_ID.0;

/// Canonical management schema. This constant is BLAKE2b-256 over
/// `vos/agent/control-schema` followed by [`CONTROL_SCHEMA_DESCRIPTOR`].
pub const CONTROL_SCHEMA_ID: Hash = Hash([
    0x8d, 0xaf, 0xeb, 0xfc, 0x65, 0xb0, 0x61, 0x1e, 0x00, 0x2b, 0xc8, 0x0e, 0xf5, 0x50, 0xb5, 0xd7,
    0x7b, 0xef, 0x69, 0x58, 0x7a, 0x21, 0x18, 0xd3, 0x6a, 0x7e, 0x61, 0x3f, 0x87, 0xf5, 0x0c, 0x37,
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
}

impl RuntimeResourceLimits {
    pub const fn standard() -> Self {
        Self {
            max_runtime_state_bytes: MAX_RUNTIME_STATE_BYTES as u32,
            max_artifact_references: MAX_CATALOG_ARTIFACT_REFERENCES,
            max_artifact_referenced_bytes: MAX_CATALOG_ARTIFACT_REFERENCED_BYTES,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.max_runtime_state_bytes != 0
            && self.max_runtime_state_bytes <= MAX_RUNTIME_STATE_BYTES as u32
            && self.max_artifact_references != 0
            && self.max_artifact_references <= MAX_CATALOG_ARTIFACT_REFERENCES
            && self.max_artifact_referenced_bytes != 0
            && self.max_artifact_referenced_bytes <= MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
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
    }

    #[test]
    fn control_schema_pin_matches_descriptor() {
        assert_eq!(
            Hash::digest(b"vos/agent/control-schema", &[CONTROL_SCHEMA_DESCRIPTOR]).0,
            CONTROL_SCHEMA_ID.0
        );
    }
}
