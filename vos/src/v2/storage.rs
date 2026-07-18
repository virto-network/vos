//! Clean-break persistent store header.

use alloc::vec::Vec;

use super::wire::{DecodeError, Decoder, Encoder, V2Wire};
use super::{DeploymentId, Hash};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreHeaderV2 {
    pub deployment: DeploymentId,
    pub execution_semantics: Hash,
    pub snapshot_version: u16,
}

impl StoreHeaderV2 {
    pub fn current(deployment: DeploymentId) -> Self {
        Self {
            deployment,
            execution_semantics: super::EXECUTION_SEMANTICS_ID,
            snapshot_version: super::SNAPSHOT_VERSION,
        }
    }

    pub fn open(bytes: &[u8]) -> Result<Self, StoreOpenError> {
        if bytes.get(..4) != Some(&Self::MAGIC) {
            return Err(StoreOpenError::LegacyStore);
        }
        let header = Self::decode(bytes).map_err(StoreOpenError::InvalidHeader)?;
        if header.execution_semantics != super::EXECUTION_SEMANTICS_ID
            || header.snapshot_version != super::SNAPSHOT_VERSION
        {
            return Err(StoreOpenError::IncompatibleSemantics);
        }
        Ok(header)
    }
}

impl V2Wire for StoreHeaderV2 {
    const MAGIC: [u8; 4] = *b"VST2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.fixed(&self.deployment.0);
        encoder.fixed(&self.execution_semantics.0);
        encoder.u16(self.snapshot_version);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            deployment: DeploymentId(decoder.fixed()?),
            execution_semantics: Hash(decoder.fixed()?),
            snapshot_version: decoder.u16()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOpenError {
    LegacyStore,
    InvalidHeader(DecodeError),
    IncompatibleSemantics,
}

impl core::fmt::Display for StoreOpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LegacyStore => f.write_str(
                "this is a VOS v1 store; runtime v2 cannot migrate it—export any needed data, \
                 reset the store, and reinstall the signed .vos package",
            ),
            Self::InvalidHeader(error) => write!(f, "invalid VOS v2 store header: {error}"),
            Self::IncompatibleSemantics => {
                f.write_str("store execution semantics do not match this runtime; reinstall")
            }
        }
    }
}

impl core::error::Error for StoreOpenError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_store_gets_actionable_clean_break_error() {
        let error = StoreHeaderV2::open(b"legacy-state").unwrap_err();
        assert_eq!(error, StoreOpenError::LegacyStore);
        let message = error.to_string();
        assert!(message.contains("reset"));
        assert!(message.contains("reinstall"));
    }

    #[test]
    fn current_header_roundtrips() {
        let header = StoreHeaderV2::current(DeploymentId([7; 32]));
        assert_eq!(StoreHeaderV2::open(&header.encode()).unwrap(), header);
    }
}
