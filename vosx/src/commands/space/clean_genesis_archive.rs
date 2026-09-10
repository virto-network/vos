//! Durable local root archive for the first clean system Agent.
//!
//! The archive owns one exact proposal/provision/catalog tuple.  A fresh
//! proposal is certified by the explicitly supplied one-voter root key and
//! published as one crash-safe whole image before it is returned to the host.
//! Reopen is read-only and never re-signs already published evidence.

use std::sync::Mutex;

use libp2p::identity::{KeyType, Keypair};
use vos::agent::bootstrap::{
    SystemAgentGenesisLocator, SystemAgentGenesisProposal, SystemAgentGenesisProvider,
    SystemAgentGenesisProviderError, SystemAgentGenesisProvision,
    validate_system_agent_genesis_catalog,
};
use vos::agent::committee::{
    AuthorityCommittee, AuthorityCommitteeMember, AuthorityMemberRole, AuthorityQuorumCertificate,
    AuthoritySignature, AuthoritySignerId, RootAnchorPins, RootAnchorRecord,
    SystemAgentGenesisClaim, SystemAgentGenesisEvidence,
};
use vos::agent::execution::RuntimeBlob;
use vos::agent::sdk::RUNTIME_ABI_ID;
use vos::service::{AgentId, Hash, NodeId, SpaceId};
use vos::service::{BlobRef, ServiceWire as _};

use super::clean_store::{
    CleanFileStoreError, CleanSystemAgentGenesisFile, MAX_CLEAN_SYSTEM_AGENT_GENESIS_ARCHIVE_BYTES,
};

const ARCHIVE_MAGIC: [u8; 4] = *b"CGA1";
const ARCHIVE_VERSION: u8 = 1;
const ARCHIVE_HEADER_BYTES: usize = 4 + 1 + 3 + 32 + 8 + 8;

/// Single-writer, root-certified implementation of the system-genesis
/// provider boundary.
pub(crate) struct CleanSystemAgentGenesisArchive {
    store: Mutex<CleanSystemAgentGenesisFile>,
    space: SpaceId,
    agent: AgentId,
    node: NodeId,
    authority_binding: Hash,
    signer: Keypair,
}

impl CleanSystemAgentGenesisArchive {
    pub(crate) fn new(
        store: CleanSystemAgentGenesisFile,
        space: SpaceId,
        agent: AgentId,
        node: NodeId,
        authority_binding: Hash,
        signer: Keypair,
    ) -> Result<Self, SystemAgentGenesisProviderError> {
        if space == SpaceId::ZERO
            || agent == AgentId::ZERO
            || node == NodeId::ZERO
            || authority_binding == Hash::ZERO
            || signer.key_type() != KeyType::Ed25519
        {
            return Err(SystemAgentGenesisProviderError::Refused);
        }
        let public_key = signer
            .public()
            .try_into_ed25519()
            .map_err(|_| SystemAgentGenesisProviderError::Refused)?
            .to_bytes();
        AuthorityCommitteeMember::new(node, public_key, AuthorityMemberRole::Voter)
            .map_err(|_| SystemAgentGenesisProviderError::Refused)?;
        Ok(Self {
            store: Mutex::new(store),
            space,
            agent,
            node,
            authority_binding,
            signer,
        })
    }

    /// Certify and publish the exact fresh bundle before its plan becomes
    /// visible. This is the callback passed to `prepare_root_authorized`.
    pub(crate) fn certify_fresh(
        &self,
        root_certification: Hash,
        proposal: &SystemAgentGenesisProposal,
        catalog: &[RuntimeBlob],
    ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError> {
        proposal
            .validate()
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        validate_system_agent_genesis_catalog(proposal, catalog)
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let locator = proposal.locator();
        if root_certification == Hash::ZERO
            || locator.space != self.space
            || locator.agent != self.agent
            || locator.node != self.node
            || proposal.replica().node != locator.node
        {
            return Err(SystemAgentGenesisProviderError::Refused);
        }
        let public_key = self
            .signer
            .public()
            .try_into_ed25519()
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?
            .to_bytes();
        let member =
            AuthorityCommitteeMember::new(self.node, public_key, AuthorityMemberRole::Voter)
                .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let committee =
            AuthorityCommittee::new(self.space, self.authority_binding, 1, None, vec![member])
                .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let root = RootAnchorRecord::new(
            1,
            self.space,
            self.agent,
            self.authority_binding,
            root_certification,
            committee,
        )
        .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let claim = SystemAgentGenesisClaim::new(&root, proposal.expectations())
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let committee = root.initial_committee();
        let message = AuthorityQuorumCertificate::signing_message(
            committee.authority_binding(),
            committee.epoch(),
            committee.commitment(),
            claim.authority_claim(),
        );
        let signature: [u8; 64] = self
            .signer
            .sign(&message.0)
            .map_err(|_| SystemAgentGenesisProviderError::Unavailable)?
            .try_into()
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let signature =
            AuthoritySignature::new(AuthoritySignerId::of_raw_ed25519(&public_key), signature)
                .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let certificate =
            AuthorityQuorumCertificate::new(committee, claim.authority_claim(), vec![signature])
                .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let evidence = SystemAgentGenesisEvidence::new(claim.clone(), certificate)
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let pins = RootAnchorPins::new(
            root.clone(),
            root.config_version(),
            root.id(),
            root.config_commitment(),
            claim.authority_claim(),
        )
        .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let candidate = ArchiveImage {
            provision: SystemAgentGenesisProvision::new(proposal.clone(), pins, evidence)
                .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?,
            catalog: catalog.to_vec(),
        };
        self.publish_candidate(candidate)
    }

    fn load_archive(&self) -> Result<Option<ArchiveImage>, SystemAgentGenesisProviderError> {
        let bytes = self
            .store
            .lock()
            .map_err(|_| SystemAgentGenesisProviderError::Unavailable)?
            .load()
            .map_err(map_store_error)?;
        bytes.as_deref().map(decode_archive).transpose()
    }

    fn publish_candidate(
        &self,
        candidate: ArchiveImage,
    ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError> {
        let candidate_bytes = encode_archive(&candidate)?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| SystemAgentGenesisProviderError::Unavailable)?;
        if let Some(existing_bytes) = store.load().map_err(map_store_error)? {
            let existing = decode_archive(&existing_bytes)?;
            return if existing == candidate {
                Ok(existing.provision)
            } else {
                Err(SystemAgentGenesisProviderError::Conflict)
            };
        }
        store.commit(&candidate_bytes).map_err(map_store_error)?;
        let published = store
            .load()
            .map_err(map_store_error)?
            .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
        if published != candidate_bytes {
            return Err(SystemAgentGenesisProviderError::Corrupt);
        }
        Ok(candidate.provision)
    }
}

impl SystemAgentGenesisProvider for CleanSystemAgentGenesisArchive {
    fn create(
        &self,
        proposal: &SystemAgentGenesisProposal,
        catalog: &[RuntimeBlob],
    ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError> {
        validate_system_agent_genesis_catalog(proposal, catalog)
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let existing = self
            .load_archive()?
            .ok_or(SystemAgentGenesisProviderError::NotConfigured)?;
        if existing.provision.proposal() == proposal && existing.catalog == catalog {
            Ok(existing.provision)
        } else {
            Err(SystemAgentGenesisProviderError::Conflict)
        }
    }

    fn reproduce(
        &self,
        locator: SystemAgentGenesisLocator,
    ) -> Result<SystemAgentGenesisProvision, SystemAgentGenesisProviderError> {
        locator
            .validate()
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let archive = self
            .load_archive()?
            .ok_or(SystemAgentGenesisProviderError::NotConfigured)?;
        if archive.provision.proposal().locator() != locator {
            return Err(SystemAgentGenesisProviderError::NotConfigured);
        }
        Ok(archive.provision)
    }

    fn load_catalog(
        &self,
        locator: SystemAgentGenesisLocator,
        reference: &BlobRef,
    ) -> Result<Option<Vec<u8>>, SystemAgentGenesisProviderError> {
        locator
            .validate()
            .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
        let Some(archive) = self.load_archive()? else {
            return Ok(None);
        };
        if archive.provision.proposal().locator() != locator {
            return Ok(None);
        }
        Ok(archive
            .catalog
            .into_iter()
            .find(|blob| &blob.reference == reference)
            .map(|blob| blob.bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ArchiveImage {
    provision: SystemAgentGenesisProvision,
    catalog: Vec<RuntimeBlob>,
}

fn encode_archive(image: &ArchiveImage) -> Result<Vec<u8>, SystemAgentGenesisProviderError> {
    validate_system_agent_genesis_catalog(image.provision.proposal(), &image.catalog)
        .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
    let [catalog] = image.catalog.as_slice() else {
        return Err(SystemAgentGenesisProviderError::Corrupt);
    };
    let provision = image.provision.encode();
    let provision_len =
        u64::try_from(provision.len()).map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
    let catalog_len =
        u64::try_from(catalog.bytes.len()).map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
    let total = ARCHIVE_HEADER_BYTES
        .checked_add(provision.len())
        .and_then(|length| length.checked_add(catalog.bytes.len()))
        .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
    if total > MAX_CLEAN_SYSTEM_AGENT_GENESIS_ARCHIVE_BYTES {
        return Err(SystemAgentGenesisProviderError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&ARCHIVE_MAGIC);
    bytes.push(ARCHIVE_VERSION);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    bytes.extend_from_slice(&provision_len.to_le_bytes());
    bytes.extend_from_slice(&catalog_len.to_le_bytes());
    bytes.extend_from_slice(&provision);
    bytes.extend_from_slice(&catalog.bytes);
    Ok(bytes)
}

fn decode_archive(bytes: &[u8]) -> Result<ArchiveImage, SystemAgentGenesisProviderError> {
    if bytes.len() < ARCHIVE_HEADER_BYTES
        || bytes.len() > MAX_CLEAN_SYSTEM_AGENT_GENESIS_ARCHIVE_BYTES
        || bytes.get(..4) != Some(ARCHIVE_MAGIC.as_slice())
        || bytes.get(4) != Some(&ARCHIVE_VERSION)
        || bytes.get(5..8) != Some([0; 3].as_slice())
        || bytes.get(8..40) != Some(RUNTIME_ABI_ID.as_bytes().as_slice())
    {
        return Err(SystemAgentGenesisProviderError::Corrupt);
    }
    let provision_len = read_length(bytes, 40)?;
    let catalog_len = read_length(bytes, 48)?;
    let provision_end = ARCHIVE_HEADER_BYTES
        .checked_add(provision_len)
        .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
    let catalog_end = provision_end
        .checked_add(catalog_len)
        .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
    if catalog_end != bytes.len() {
        return Err(SystemAgentGenesisProviderError::Corrupt);
    }
    let provision = SystemAgentGenesisProvision::decode(
        bytes
            .get(ARCHIVE_HEADER_BYTES..provision_end)
            .ok_or(SystemAgentGenesisProviderError::Corrupt)?,
    )
    .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
    let catalog_bytes = bytes
        .get(provision_end..catalog_end)
        .ok_or(SystemAgentGenesisProviderError::Corrupt)?
        .to_vec();
    let reference = BlobRef::of_bytes(&catalog_bytes);
    let catalog = vec![RuntimeBlob {
        reference,
        bytes: catalog_bytes,
    }];
    validate_system_agent_genesis_catalog(provision.proposal(), &catalog)
        .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
    let image = ArchiveImage { provision, catalog };
    if encode_archive(&image)?.as_slice() != bytes {
        return Err(SystemAgentGenesisProviderError::Corrupt);
    }
    Ok(image)
}

fn read_length(bytes: &[u8], offset: usize) -> Result<usize, SystemAgentGenesisProviderError> {
    let end = offset
        .checked_add(8)
        .ok_or(SystemAgentGenesisProviderError::Corrupt)?;
    let raw: [u8; 8] = bytes
        .get(offset..end)
        .ok_or(SystemAgentGenesisProviderError::Corrupt)?
        .try_into()
        .map_err(|_| SystemAgentGenesisProviderError::Corrupt)?;
    usize::try_from(u64::from_le_bytes(raw)).map_err(|_| SystemAgentGenesisProviderError::Corrupt)
}

fn map_store_error(error: CleanFileStoreError) -> SystemAgentGenesisProviderError {
    match error {
        CleanFileStoreError::Io(_)
        | CleanFileStoreError::Busy
        | CleanFileStoreError::LockPoisoned => SystemAgentGenesisProviderError::Unavailable,
        _ => SystemAgentGenesisProviderError::Corrupt,
    }
}
