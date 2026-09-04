//! Signed compatibility contract between actor and agent-runtime packages.
//!
//! Capability flags describe optional behavior. This module describes the
//! mandatory execution and control protocol that lets an actor package run
//! under a particular agent runtime without pinning that runtime's program.

use crate::service::Hash;
use crate::service::wire::{DecodeError, Decoder, Encoder};

/// Actor entry ABI emitted by the canonical actor toolchain.
pub const ACTOR_ABI: u32 = 1;

/// Canonical management schema implemented by every agent runtime.
///
/// The value is BLAKE2b-256 over `vos/agent/control-schema` followed by the
/// lifecycle ABI identity. The lifecycle ABI commits to the complete request,
/// reply, authority-evidence, and state wire. Its test below forces an explicit
/// control-schema repin whenever that wire identity changes.
pub const CONTROL_SCHEMA_DESCRIPTOR: &[u8] = &super::RUNTIME_ABI_ID.0;
pub const CONTROL_SCHEMA_ID: Hash = Hash([
    0xf5, 0x38, 0x67, 0xf0, 0xe9, 0xc4, 0xe9, 0x73, 0x2d, 0xb9, 0x30, 0x4b, 0x05, 0x4d, 0x83, 0x84,
    0x5e, 0xc1, 0x9b, 0xa6, 0x52, 0x15, 0x33, 0x87, 0x87, 0x9f, 0xeb, 0xf9, 0x49, 0xae, 0x53, 0x99,
]);

/// Standard runtime directory capacity. This is an agent policy limit, not
/// the PVM limit of 63 simultaneously active inner machines.
pub const STANDARD_MAX_ACTORS: u32 = 4_096;

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

    pub const fn is_valid(self) -> bool {
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
/// the package.
///
/// Actor count and state bytes are separate resources: supporting 4,096
/// directory entries does not promise that 4,096 maximum-sized actors fit in
/// one image. Artifact limits count exact `(hash, encoded_len)` references,
/// so shared content is charged once while a hash presented with two lengths
/// is never a canonical closure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeResourceLimits {
    pub max_runtime_state_bytes: u32,
    pub max_artifact_references: u32,
    pub max_artifact_referenced_bytes: u64,
}

impl RuntimeResourceLimits {
    pub const fn standard() -> Self {
        Self {
            max_runtime_state_bytes: super::execution::MAX_RUNTIME_STATE_BYTES as u32,
            max_artifact_references: super::MAX_CATALOG_ARTIFACT_REFERENCES,
            max_artifact_referenced_bytes: super::MAX_CATALOG_ARTIFACT_REFERENCED_BYTES,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.max_runtime_state_bytes != 0
            && self.max_runtime_state_bytes <= super::execution::MAX_RUNTIME_STATE_BYTES as u32
            && self.max_artifact_references != 0
            && self.max_artifact_references <= super::MAX_CATALOG_ARTIFACT_REFERENCES
            && self.max_artifact_referenced_bytes != 0
            && self.max_artifact_referenced_bytes <= super::MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
    }
}

/// Durable state migration behavior implemented by a runtime package.
///
/// No migration protocol is currently supported. Adding one requires a new
/// explicit enum case and package-validation rule; unknown wire tags fail
/// closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RuntimeMigrationPolicy {
    None = 0,
}

/// Complete mandatory contract signed into an agent-runtime package.
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
            lifecycle_abi: super::RUNTIME_ABI_ID,
            actor_abis: ActorAbiRange::exact(ACTOR_ABI),
            control_schema: CONTROL_SCHEMA_ID,
            resources: RuntimeResourceLimits::standard(),
            migration: RuntimeMigrationPolicy::None,
        }
    }

    pub fn is_valid(self) -> bool {
        self.lifecycle_abi.0 == super::RUNTIME_ABI_ID.0
            && self.actor_abis.is_valid()
            && self.control_schema.0 == CONTROL_SCHEMA_ID.0
            && self.resources.is_valid()
            && matches!(self.migration, RuntimeMigrationPolicy::None)
    }

    pub fn supports(self, actor: ActorPackageContract) -> bool {
        self.is_valid() && actor.is_valid() && self.actor_abis.supports(actor.actor_abi)
    }
}

pub(crate) fn encode_actor_contract(encoder: &mut Encoder<'_>, contract: ActorPackageContract) {
    encoder.u32(contract.actor_abi);
}

pub(crate) fn decode_actor_contract(
    decoder: &mut Decoder<'_>,
) -> Result<ActorPackageContract, DecodeError> {
    let contract = ActorPackageContract {
        actor_abi: decoder.u32()?,
    };
    if !contract.is_valid() {
        return Err(DecodeError::NonCanonical);
    }
    Ok(contract)
}

pub(crate) fn encode_runtime_contract(encoder: &mut Encoder<'_>, contract: RuntimePackageContract) {
    encoder.fixed(&contract.lifecycle_abi.0);
    encoder.u32(contract.actor_abis.minimum);
    encoder.u32(contract.actor_abis.maximum);
    encoder.fixed(&contract.control_schema.0);
    encoder.u32(contract.resources.max_runtime_state_bytes);
    encoder.u32(contract.resources.max_artifact_references);
    encoder.u64(contract.resources.max_artifact_referenced_bytes);
    encoder.u8(contract.migration as u8);
}

pub(crate) fn decode_runtime_contract(
    decoder: &mut Decoder<'_>,
) -> Result<RuntimePackageContract, DecodeError> {
    let contract = RuntimePackageContract {
        lifecycle_abi: Hash(decoder.fixed()?),
        actor_abis: ActorAbiRange {
            minimum: decoder.u32()?,
            maximum: decoder.u32()?,
        },
        control_schema: Hash(decoder.fixed()?),
        resources: RuntimeResourceLimits {
            max_runtime_state_bytes: decoder.u32()?,
            max_artifact_references: decoder.u32()?,
            max_artifact_referenced_bytes: decoder.u64()?,
        },
        migration: match decoder.u8()? {
            0 => RuntimeMigrationPolicy::None,
            _ => return Err(DecodeError::InvalidTag),
        },
    };
    if !contract.actor_abis.is_valid() || !contract.resources.is_valid() {
        return Err(DecodeError::NonCanonical);
    }
    Ok(contract)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_schema_pin_matches_its_canonical_descriptor() {
        assert_eq!(
            super::super::RUNTIME_ABI_ID.0,
            *b"vos-agent-runtime-abi-20260904r7"
        );
        assert_eq!(
            super::super::EXECUTION_SEMANTICS_ID.0,
            *b"vos-pvm-41d31e6-standard-gas-r04"
        );
        assert_eq!(
            Hash::digest(b"vos/agent/control-schema", &[CONTROL_SCHEMA_DESCRIPTOR]),
            CONTROL_SCHEMA_ID
        );
    }

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
                maximum: 2,
            }
            .is_valid()
        );
    }

    #[test]
    fn canonical_runtime_contract_is_explicit_and_bounded() {
        let contract = RuntimePackageContract::canonical();
        assert!(contract.is_valid());
        assert!(contract.supports(ActorPackageContract::canonical()));
        assert_eq!(STANDARD_MAX_ACTORS, 4_096);
        assert_eq!(super::super::MAX_CATALOG_ARTIFACT_REFERENCES, 12_289);
        assert_eq!(
            contract.resources.max_runtime_state_bytes,
            super::super::execution::MAX_RUNTIME_STATE_BYTES as u32
        );
        assert_eq!(
            contract.resources.max_artifact_references,
            super::super::MAX_CATALOG_ARTIFACT_REFERENCES
        );
        assert_eq!(
            contract.resources.max_artifact_referenced_bytes,
            super::super::MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
        );
        assert_eq!(contract.migration, RuntimeMigrationPolicy::None);
    }

    #[test]
    fn runtime_resource_limits_are_nonzero_and_canonically_bounded() {
        let canonical = RuntimeResourceLimits::standard();
        assert!(canonical.is_valid());

        for invalid in [
            RuntimeResourceLimits {
                max_runtime_state_bytes: 0,
                ..canonical
            },
            RuntimeResourceLimits {
                max_runtime_state_bytes: super::super::execution::MAX_RUNTIME_STATE_BYTES as u32
                    + 1,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_references: 0,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_references: super::super::MAX_CATALOG_ARTIFACT_REFERENCES + 1,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_referenced_bytes: 0,
                ..canonical
            },
            RuntimeResourceLimits {
                max_artifact_referenced_bytes: super::super::MAX_CATALOG_ARTIFACT_REFERENCED_BYTES
                    + 1,
                ..canonical
            },
        ] {
            assert!(!invalid.is_valid());
            let contract = RuntimePackageContract {
                resources: invalid,
                ..RuntimePackageContract::canonical()
            };
            let mut bytes = alloc::vec::Vec::new();
            encode_runtime_contract(&mut Encoder(&mut bytes), contract);
            assert_eq!(
                decode_runtime_contract(&mut Decoder::new(&bytes)),
                Err(DecodeError::NonCanonical)
            );
        }
    }

    #[test]
    fn runtime_resource_limits_round_trip_in_the_signed_contract_wire() {
        let mut contract = RuntimePackageContract::canonical();
        contract.resources.max_runtime_state_bytes = 1;
        contract.resources.max_artifact_references = 2;
        contract.resources.max_artifact_referenced_bytes = 3;
        let mut bytes = alloc::vec::Vec::new();
        encode_runtime_contract(&mut Encoder(&mut bytes), contract);
        let mut decoder = Decoder::new(&bytes);
        assert_eq!(decode_runtime_contract(&mut decoder), Ok(contract));
        assert!(decoder.exhausted());
    }
}
