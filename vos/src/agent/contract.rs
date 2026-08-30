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
    0x60, 0x95, 0x76, 0xc0, 0x06, 0x2d, 0xc6, 0xa8, 0x42, 0x75, 0xf2, 0xa6, 0xd5, 0x37, 0x57, 0x40,
    0x1f, 0x23, 0x0a, 0xde, 0x08, 0x42, 0x2c, 0xee, 0x09, 0xef, 0xb0, 0x6d, 0xf1, 0xd6, 0x7b, 0xb6,
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

/// Runtime-owned state-image ceiling authenticated by the package.
///
/// Actor count and state bytes are separate resources: supporting 4,096
/// directory entries does not promise that 4,096 maximum-sized actors fit in
/// one image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeResourceLimits {
    pub max_runtime_state_bytes: u32,
}

impl RuntimeResourceLimits {
    pub const fn standard() -> Self {
        Self {
            max_runtime_state_bytes: super::execution::MAX_RUNTIME_STATE_BYTES as u32,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.max_runtime_state_bytes != 0
            && self.max_runtime_state_bytes <= super::execution::MAX_RUNTIME_STATE_BYTES as u32
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
        assert_eq!(
            contract.resources.max_runtime_state_bytes,
            super::super::execution::MAX_RUNTIME_STATE_BYTES as u32
        );
        assert_eq!(contract.migration, RuntimeMigrationPolicy::None);
    }
}
