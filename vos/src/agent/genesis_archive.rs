//! Immutable ordinary-genesis archive access. This is not a signer or a
//! finality verifier; only previously archived provisions can be reproduced.

use alloc::vec::Vec;
use super::execution::RuntimeBlob;
use super::genesis::{
    AgentGenesisArchiveRecord, AgentGenesisLocator, AgentGenesisProposal,
    AgentGenesisProvider, AgentGenesisProviderError as Error, AgentGenesisProvision,
    MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES, validate_agent_genesis_catalog,
};
use crate::service::{BlobRef, ServiceWire, SpaceId};

/// Single-owner durable per-locator storage. Reads must enforce the record-size
/// bound before allocating. Publication is atomic, never overwrites an existing
/// locator, and returns success only after the stored record is durable.
/// An error may follow a durable write; callers must reload before retrying.
pub trait AgentGenesisArchiveStore: Send + Sync {
    type Error;
    fn load(&self, locator: AgentGenesisLocator) -> Result<Option<Vec<u8>>, Self::Error>;
    fn insert_if_absent(&self, locator: AgentGenesisLocator, record: &[u8]) -> Result<(), Self::Error>;
}

/// Provider backed by exact archived provisions. `create` only reproduces an
/// already archived matching record; issuance and policy publication belong
/// to the coordinator, not this archive. No result carries trusted finality.
pub struct ArchivedAgentGenesisProvider<S> {
    space: SpaceId,
    store: S,
}

impl<S: AgentGenesisArchiveStore> ArchivedAgentGenesisProvider<S> {
    pub fn new(space: SpaceId, store: S) -> Result<Self, Error> {
        if space == SpaceId::ZERO { return Err(Error::Refused); }
        Ok(Self { space, store })
    }

    /// Read structurally validated archive data, not trusted finality evidence.
    pub fn load_record(&self, locator: AgentGenesisLocator) -> Result<Option<AgentGenesisArchiveRecord>, Error> {
        locator.validate().map_err(|_| Error::Refused)?;
        if locator.space != self.space { return Err(Error::Refused); }
        let Some(bytes) = self.store.load(locator).map_err(|_| Error::Unavailable)? else {
            return Ok(None);
        };
        if bytes.len() > MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES { return Err(Error::Corrupt); }
        let record = AgentGenesisArchiveRecord::decode(&bytes).map_err(|_| Error::Corrupt)?;
        if record.provision().proposal().locator() != locator { return Err(Error::Corrupt); }
        Ok(Some(record))
    }

    /// Publish an externally issued, structurally valid record. A successful
    /// return means durable byte identity only, never authenticated finality.
    pub fn publish(&self, record: &AgentGenesisArchiveRecord) -> Result<(), Error> {
        let locator = record.provision().proposal().locator();
        if let Some(existing) = self.load_record(locator)? {
            if existing != *record { return Err(Error::Conflict); }
        }
        let bytes = record.encode();
        if bytes.len() > MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES { return Err(Error::Refused); }
        self.store.insert_if_absent(locator, &bytes).map_err(|_| Error::Unavailable)?;
        // Reload even after success: another publisher may have won the
        // immutable insertion, and an implementation must not lose the write.
        match self.load_record(locator)? {
            Some(existing) if existing == *record => Ok(()),
            Some(_) => Err(Error::Conflict),
            None => Err(Error::Corrupt),
        }
    }
}

impl<S: AgentGenesisArchiveStore> AgentGenesisProvider for ArchivedAgentGenesisProvider<S> {
    fn create(&self, proposal: &AgentGenesisProposal, catalog: &[RuntimeBlob]) -> Result<AgentGenesisProvision, Error> {
        validate_agent_genesis_catalog(proposal, catalog).map_err(|_| Error::Refused)?;
        let record = self.load_record(proposal.locator())?.ok_or(Error::NotConfigured)?;
        if record.provision().proposal() != proposal || record.catalog() != catalog {
            return Err(Error::Conflict);
        }
        Ok(record.provision().clone())
    }

    fn reproduce(&self, locator: AgentGenesisLocator) -> Result<AgentGenesisProvision, Error> {
        self.load_record(locator)?.map(|record| record.provision().clone()).ok_or(Error::NotConfigured)
    }

    fn load_catalog(&self, locator: AgentGenesisLocator, reference: &BlobRef) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.load_record(locator)?.and_then(|record| {
            record.catalog().iter().find(|blob| &blob.reference == reference).map(|blob| blob.bytes.clone())
        }))
    }
}
