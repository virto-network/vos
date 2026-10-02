//! Member-only public OGAR storage. A readable or durable archive proves byte
//! identity, never finality, host admission, a route, or public Create success.
//! The controller must obtain its fresh Core member proof before publication
//! or admission, and retain these independent archive leases until shutdown.

use super::*;
use vos::agent::genesis::{AgentGenesisArchiveRecord, AgentGenesisLocator};
use vos::agent::genesis_archive::AgentGenesisArchiveStore as _;
use vos::service::{NodeId, ServiceWire as _, SpaceId};

const MEMBER_DIRECTORY: &str = "shared-agent-members";

pub(crate) struct CleanSharedMemberGenesisEntry {
    pub(crate) locator: AgentGenesisLocator,
    pub(crate) archive: CleanAgentGenesisArchiveFile,
    // None is an interrupted preparation, not an admitted generation.
    pub(crate) record: Option<AgentGenesisArchiveRecord>,
}

/// Pins the configured Space root. No lifecycle/issuer/committee namespace is
/// created, and existing origin-owned archive orphan checks remain unchanged.
pub(crate) struct CleanSharedMemberGenesisFiles {
    data_dir: PathBuf,
    directory: File,
    space: SpaceId,
    node: NodeId,
    maximum: usize,
    archives: Option<CleanAgentGenesisArchiveStoreFactory>,
}

impl CleanSharedMemberGenesisFiles {
    pub(crate) fn open(
        data_dir: &Path,
        space: SpaceId,
        node: NodeId,
        maximum: usize,
    ) -> Result<Self, CleanFileStoreError> {
        if space == SpaceId::ZERO
            || node == NodeId::ZERO
            || maximum == 0
            || maximum > vos::agent::shared_host::MAX_SHARED_HOST_AGENTS
        {
            return Err(CleanFileStoreError::InvalidPath);
        }
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            directory: open_private_directory(data_dir, true)?,
            space,
            node,
            maximum,
            archives: None,
        })
    }

    fn factory(
        &mut self,
        create: bool,
    ) -> Result<Option<&CleanAgentGenesisArchiveStoreFactory>, CleanFileStoreError> {
        validate_opened_directory(&self.directory, &self.data_dir, true)?;
        let path = self.data_dir.join(MEMBER_DIRECTORY);
        if self.archives.is_none() {
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => (),
                Ok(_) => return Err(CleanFileStoreError::InvalidPath),
                Err(error) if error.kind() == io::ErrorKind::NotFound && !create => {
                    return Ok(None);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    ensure_private_directory(&path)?;
                }
                Err(error) => return Err(error.into()),
            }
            self.archives = Some(CleanAgentGenesisArchiveStoreFactory::open_existing(
                &path, self.space,
            )?);
        }
        validate_opened_directory(&self.directory, &self.data_dir, true)?;
        let archives = self.archives.as_ref().unwrap();
        validate_opened_directory(&archives.directory, &archives.parent, true)?;
        Ok(Some(archives))
    }

    /// Complete bounded, noncreating discovery. Empty preparations remain
    /// leased but cannot be used as finalized member evidence.
    pub(crate) fn discover(
        &mut self,
    ) -> Result<Vec<CleanSharedMemberGenesisEntry>, CleanFileStoreError> {
        let maximum = self.maximum;
        let Some(archives) = self.factory(false)? else {
            return Ok(Vec::new());
        };
        let locators = archives.discover(maximum)?;
        let mut entries = Vec::with_capacity(locators.len());
        for locator in &locators {
            entries.push(self.open_existing(*locator)?);
        }
        if self.factory(false)?.unwrap().discover(maximum)? != locators {
            return Err(CleanFileStoreError::UnexpectedResidue);
        }
        Ok(entries)
    }

    pub(crate) fn open_existing(
        &mut self,
        locator: AgentGenesisLocator,
    ) -> Result<CleanSharedMemberGenesisEntry, CleanFileStoreError> {
        if locator.space != self.space || locator.validate().is_err() {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let archive = self
            .factory(false)?
            .ok_or(CleanFileStoreError::UnexpectedResidue)?
            .open_archive(locator)?;
        self.entry(locator, archive)
    }

    /// Storage preparation only. Core must separately verify current finalized
    /// membership before its callback inserts these bytes or admits the host.
    /// An existing controller-owned locator reuses its already retained lease.
    pub(crate) fn prepare_insert(
        &mut self,
        bytes: &[u8],
    ) -> Result<CleanSharedMemberGenesisEntry, CleanFileStoreError> {
        if bytes.len() > vos::agent::genesis::MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES {
            return Err(CleanFileStoreError::Oversized);
        }
        let record =
            AgentGenesisArchiveRecord::decode(bytes).map_err(|_| CleanFileStoreError::Corrupt)?;
        let locator = record.provision().proposal().locator();
        self.validate_record(locator, &record)?;
        let maximum = self.maximum;
        let found = self
            .factory(false)?
            .map(|factory| factory.discover(maximum))
            .transpose()?
            .unwrap_or_default();
        if !found.contains(&locator) && found.len() >= maximum {
            return Err(CleanFileStoreError::Oversized);
        }
        let archive = {
            let archives = self.factory(true)?.unwrap();
            let archive = CleanAgentGenesisArchiveFile::open_or_create(&archives.parent, locator)?;
            validate_opened_directory(&archives.directory, &archives.parent, true)?;
            archive
        };
        let entry = self.entry(locator, archive)?;
        if entry
            .record
            .as_ref()
            .is_some_and(|existing| existing != &record)
        {
            return Err(CleanFileStoreError::RequestConflict);
        }
        Ok(entry)
    }

    fn entry(
        &self,
        locator: AgentGenesisLocator,
        archive: CleanAgentGenesisArchiveFile,
    ) -> Result<CleanSharedMemberGenesisEntry, CleanFileStoreError> {
        let record = archive
            .load(locator)?
            .map(
                |bytes| -> Result<AgentGenesisArchiveRecord, CleanFileStoreError> {
                    let record = AgentGenesisArchiveRecord::decode(&bytes)
                        .map_err(|_| CleanFileStoreError::Corrupt)?;
                    self.validate_record(locator, &record)?;
                    Ok(record)
                },
            )
            .transpose()?;
        Ok(CleanSharedMemberGenesisEntry {
            locator,
            archive,
            record,
        })
    }

    fn validate_record(
        &self,
        locator: AgentGenesisLocator,
        record: &AgentGenesisArchiveRecord,
    ) -> Result<(), CleanFileStoreError> {
        if Self::validate_client_record(self.space, self.node, record)? != locator {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(())
    }

    /// Side-effect-free shape/package preflight shared with the archive client.
    /// This conveys no fresh finality, storage ownership or route permission.
    pub(crate) fn validate_client_record(
        space: SpaceId,
        node: NodeId,
        record: &AgentGenesisArchiveRecord,
    ) -> Result<AgentGenesisLocator, CleanFileStoreError> {
        use vos::agent::sdk::{AgentProfile, ReplicaRole};
        let provision = record.provision();
        let proposal = provision.proposal();
        let locator = proposal.locator();
        let descriptor = proposal
            .clean_descriptor()
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let replicas = provision.replicas();
        if locator.space != space
            || descriptor.identity.profile != AgentProfile::Shared
            || descriptor.identity.space.0 != locator.space.0
            || descriptor.identity.agent.0 != locator.agent.0
            || replicas.profile() != vos::agent::AgentProfile::Shared
            || replicas.members().len() != 3
            || replicas.voter_count() != 3
            || descriptor.replicas.len() != 3
            || descriptor
                .replicas
                .iter()
                .any(|replica| replica.role != ReplicaRole::Voter)
            || replicas.member_by_node(node).is_none()
            || replicas.members().iter().any(|member| {
                !descriptor.replicas.iter().any(|replica| {
                    let found = member.replica();
                    replica.node.0 == found.node.0
                        && replica.principal.0 == found.principal.0
                        && found.role == vos::agent::ReplicaRole::Voter
                })
            })
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        let [blob] = record.catalog() else {
            return Err(CleanFileStoreError::Corrupt);
        };
        let runtime = vos::agent::package_admission::admit_state_runtime_package(&blob.bytes)
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let binding = &proposal.create().runtime;
        if descriptor.runtime_package != *runtime.package_ref()
            || descriptor.identity.runtime_deployment != runtime.deployment()
            || descriptor.identity.runtime_program != runtime.program()
            || descriptor.identity.runtime_producer != runtime.manifest().signing.producer
            || descriptor.runtime_contract != runtime.manifest().contract
            || descriptor.capabilities != runtime.manifest().capabilities
            || binding.deployment.0 != runtime.deployment().0
            || binding.program.0 != runtime.program().0
            || binding.producer.0 != runtime.manifest().signing.producer.0
            || binding.package.hash.0 != runtime.package_ref().hash.0
            || binding.package.len != runtime.package_ref().len
            || binding.runtime_abi.0 != vos::agent::sdk::state_execution::STATE_EXECUTION_ABI_ID.0
            || binding.execution_semantics.0
                != vos::agent::sdk::state_execution::STATE_EXECUTION_SEMANTICS_ID.0
        {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(locator)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::Fixture;
    use super::*;

    fn files(fixture: &Fixture) -> CleanSharedMemberGenesisFiles {
        CleanSharedMemberGenesisFiles::open(&fixture.parent, SpaceId([1; 32]), NodeId([2; 32]), 2)
            .unwrap()
    }

    #[test]
    fn member_archives_are_noncreating_and_refuse_invalid_scope_before_creation() {
        let fixture = Fixture::new("member-genesis-empty");
        let mut files = files(&fixture);
        assert!(files.discover().unwrap().is_empty());
        assert!(files.prepare_insert(b"malformed OGAR").is_err());
        assert!(
            files
                .open_existing(AgentGenesisLocator {
                    space: SpaceId([9; 32]),
                    agent: vos::service::AgentId([3; 32])
                })
                .is_err()
        );
        assert!(
            files
                .open_existing(AgentGenesisLocator {
                    space: SpaceId([1; 32]),
                    agent: vos::service::AgentId([3; 32])
                })
                .is_err()
        );
        assert!(!fixture.parent.join(MEMBER_DIRECTORY).exists());
        assert_eq!(fs::read_dir(&fixture.parent).unwrap().count(), 0);
    }

    #[test]
    fn member_archives_refuse_malformed_namespace_and_substituted_parent() {
        let fixture = Fixture::new("member-genesis-hostile");
        let parent = fixture.parent.join(MEMBER_DIRECTORY);
        ensure_private_directory(&parent).unwrap();
        super::super::tests::write_private(&parent.join("foreign"), b"untouched");
        let mut files = files(&fixture);
        assert!(files.discover().is_err());
        assert!(files.prepare_insert(b"malformed OGAR").is_err());
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 1);
        assert_eq!(fs::read(parent.join("foreign")).unwrap(), b"untouched");
        fs::rename(&parent, fixture.parent.join("moved-members")).unwrap();
        ensure_private_directory(&parent).unwrap();
        assert!(files.discover().is_err());
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    }

    #[test]
    fn member_empty_preparations_retain_independent_exact_archive_leases() {
        let fixture = Fixture::new("member-genesis-leases");
        let parent = fixture.parent.join(MEMBER_DIRECTORY);
        ensure_private_directory(&parent).unwrap();
        let locator = AgentGenesisLocator {
            space: SpaceId([1; 32]),
            agent: vos::service::AgentId([3; 32]),
        };
        drop(CleanAgentGenesisArchiveFile::open_or_create(&parent, locator).unwrap());
        let mut files = files(&fixture);
        let entries = files.discover().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].locator, locator);
        assert!(entries[0].record.is_none());
        assert!(matches!(
            files.open_existing(locator),
            Err(CleanFileStoreError::Busy)
        ));
        drop(entries);
        let entry = files.open_existing(locator).unwrap();
        assert_eq!(entry.archive.load(locator).unwrap(), None);
        assert_eq!(fs::read_dir(&fixture.parent).unwrap().count(), 1);
    }
}
