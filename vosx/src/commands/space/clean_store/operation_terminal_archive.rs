//! Immutable native terminal preimages, keyed by either invocation. Only the
//! bounded active journal is discovered; terminal directories are never scanned
//! during requests or startup. Each touched directory has seven fixed entries.
use super::*;
#[cfg(test)]
#[path = "operation_terminal_archive_tests.rs"]
pub(super) mod tests;
use vos::agent::clean_bootstrap::{
    MAX_NATIVE_OPERATION_RETIREMENT_BYTES, native_operation_completion_invocations,
    native_operation_retired_pair_matches, native_operation_retirement_completion,
};
use vos::agent::sdk::{InvocationId, authority::AuthorityActorTarget};

const ENTRIES: &[&str] = &[
    LOCK_FILE,
    "authorization",
    "authorization.next",
    "acknowledgement",
    "acknowledgement.next",
    "retirement",
    "retirement.next",
];

pub(crate) struct NativeOperationTerminalArchive {
    path: PathBuf,
    directory: File,
    authority: AuthorityActorTarget,
    // The existing exclusive active-journal lease serializes this archive.
    owner: Arc<StoreRoot>,
}

impl NativeOperationTerminalArchive {
    pub(super) fn open(
        path: &Path,
        authority: AuthorityActorTarget,
        owner: Arc<StoreRoot>,
        create: bool,
    ) -> Result<Self, CleanFileStoreError> {
        let directory = if create {
            ensure_private_directory(path)?
        } else {
            open_private_directory(path, false)?
        };
        let archive = Self {
            path: path.to_owned(),
            directory,
            authority,
            owner,
        };
        archive.validate()?;
        Ok(archive)
    }

    fn validate(&self) -> Result<(), CleanFileStoreError> {
        self.owner.validate_path()?;
        validate_opened_directory(&self.directory, &self.path, false)
    }

    fn ids(&self, terminal: &[u8]) -> Result<[InvocationId; 2], CleanFileStoreError> {
        let completion =
            native_operation_retirement_completion(&self.authority.binding.public_key, terminal)
                .ok_or(CleanFileStoreError::Corrupt)?;
        native_operation_completion_invocations(&self.authority.binding.public_key, &completion)
            .ok_or(CleanFileStoreError::Corrupt)
    }

    fn slot(
        &self,
        id: InvocationId,
        create: bool,
    ) -> Result<Option<Arc<StoreRoot>>, CleanFileStoreError> {
        self.validate()?;
        if id == InvocationId::ZERO {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let path = self.path.join(hex::encode(id.0));
        match fs::symlink_metadata(&path) {
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound && !create => return Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        let root = Arc::new(StoreRoot::open_with_entries_mode(&path, ENTRIES, create)?);
        self.validate()?;
        Ok(Some(root))
    }

    fn files(root: &Arc<StoreRoot>) -> [ExactFileStore; 3] {
        [
            (StoreRole::OperationDispatch, "authorization"),
            (StoreRole::OperationDispatch, "acknowledgement"),
            (StoreRole::OperationRetirements, "retirement"),
        ]
        .map(|(role, name)| ExactFileStore {
            root: root.clone(),
            role,
            names: Some((name.to_owned(), format!("{name}.next"))),
        })
    }

    fn load_slot(&self, id: InvocationId) -> Result<Option<[Vec<u8>; 3]>, CleanFileStoreError> {
        let Some(root) = self.slot(id, false)? else {
            return Ok(None);
        };
        let _guard = root.guard()?;
        let mut values = Vec::new();
        for (index, file) in Self::files(&root).into_iter().enumerate() {
            let maximum = if index == 2 {
                MAX_NATIVE_OPERATION_RETIREMENT_BYTES
            } else {
                MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES
            };
            // All archive members are immutable first publications. Validate
            // candidates before reconciliation can publish an initial stage.
            let canonical = file.read_optional(file.file(), maximum)?;
            let staged = file.read_optional(file.stage_file(), maximum)?;
            if canonical
                .iter()
                .chain(staged.iter())
                .any(|image| image.predecessor.is_some())
                || matches!((&canonical, &staged), (Some(a), Some(b)) if a != b)
            {
                return Err(CleanFileStoreError::RequestConflict);
            }
            values.push(canonical.or(staged).map(|image| image.payload));
        }
        self.validate()?;
        if values.iter().all(Option::is_none) {
            return Ok(None);
        }
        let [a, b, terminal]: [Option<Vec<u8>>; 3] = values
            .try_into()
            .map_err(|_| CleanFileStoreError::Corrupt)?;
        let (Some(a), Some(b), Some(terminal)) = (a, b, terminal) else {
            return Err(CleanFileStoreError::AmbiguousPublication);
        };
        if !native_operation_retired_pair_matches(self.authority, id, &a, &b, &terminal) {
            return Err(CleanFileStoreError::Corrupt);
        }
        // Only complete, authenticated unchanged inputs permit initial-stage
        // publication. Malformed or partial stages remain in place on error.
        for (index, file) in Self::files(&root).into_iter().enumerate() {
            let maximum = if index == 2 {
                MAX_NATIVE_OPERATION_RETIREMENT_BYTES
            } else {
                MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES
            };
            file.reconcile(maximum)?
                .ok_or(CleanFileStoreError::Corrupt)?;
            file.sync_named(file.file())?;
        }
        root.sync()?;
        self.validate()?;
        Ok(Some([a, b, terminal]))
    }

    pub(super) fn load(
        &self,
        id: InvocationId,
    ) -> Result<Option<[Vec<u8>; 3]>, CleanFileStoreError> {
        let Some(record) = self.load_slot(id)? else {
            return Ok(None);
        };
        let ids = self.ids(&record[2])?;
        let other = if id == ids[0] { ids[1] } else { ids[0] };
        let alias = self
            .load_slot(other)?
            .ok_or(CleanFileStoreError::AmbiguousPublication)?;
        if alias != record {
            return Err(CleanFileStoreError::RequestConflict);
        }
        Ok(Some(record))
    }

    pub(super) fn retain(
        &self,
        records: [&[u8]; 2],
        terminal: &[u8],
    ) -> Result<(), CleanFileStoreError> {
        let ids = self.ids(terminal)?;
        if !native_operation_retired_pair_matches(
            self.authority,
            ids[0],
            records[0],
            records[1],
            terminal,
        ) {
            return Err(CleanFileStoreError::Corrupt);
        }
        for id in ids {
            let root = self.slot(id, true)?.ok_or(CleanFileStoreError::Corrupt)?;
            // Publish exact full preimages first and NRT1 last. A failed write
            // cannot authorize hot pruning; retry completes the same members.
            for (mut file, bytes) in Self::files(&root)
                .into_iter()
                .zip([records[0], records[1], terminal])
            {
                for name in [file.file(), file.stage_file()] {
                    if let Some(image) = file.read_optional(name, bytes.len())? {
                        if image.predecessor.is_some() || image.payload != bytes {
                            return Err(CleanFileStoreError::RequestConflict);
                        }
                    }
                }
                file.commit_with_replacement(bytes, false)?;
            }
        }
        let loaded = self.load(ids[0])?.ok_or(CleanFileStoreError::Corrupt)?;
        if loaded[0] != records[0] || loaded[1] != records[1] || loaded[2] != terminal {
            return Err(CleanFileStoreError::RequestConflict);
        }
        Ok(())
    }

    pub(super) fn proves_certificate(
        &self,
        certificate: &[u8],
        retirement: bool,
    ) -> Result<bool, CleanFileStoreError> {
        let completion;
        let bytes = if retirement {
            completion = native_operation_retirement_completion(
                &self.authority.binding.public_key,
                certificate,
            )
            .ok_or(CleanFileStoreError::Corrupt)?;
            completion.as_slice()
        } else {
            certificate
        };
        let ids =
            native_operation_completion_invocations(&self.authority.binding.public_key, bytes)
                .ok_or(CleanFileStoreError::Corrupt)?;
        let Some(archive) = self.load(ids[0])? else {
            return Ok(false);
        };
        if retirement {
            return Ok(archive[2] == certificate);
        }
        Ok(
            native_operation_retirement_completion(&self.authority.binding.public_key, &archive[2])
                .is_some_and(|embedded| embedded == certificate),
        )
    }
}

impl CleanNativeAuthorityOperationJournal {
    pub(crate) fn with_terminal_archive(self, path: &Path) -> Result<Self, CleanFileStoreError> {
        self.with_terminal_archive_mode(path, true)
    }

    /// Supported startup permits creation only before either active image or
    /// journal has history. A missing archive afterward is loss, not repair.
    pub(crate) fn with_terminal_archive_mode(
        mut self,
        path: &Path,
        create: bool,
    ) -> Result<Self, CleanFileStoreError> {
        if self.terminal_archive.is_some() {
            return Err(CleanFileStoreError::RequestConflict);
        }
        self.terminal_archive = Some(Arc::new(NativeOperationTerminalArchive::open(
            path,
            self.authority,
            self.root.clone(),
            create,
        )?));
        Ok(self)
    }

    pub(crate) fn terminal_archive(&self) -> Option<Arc<NativeOperationTerminalArchive>> {
        self.terminal_archive.clone()
    }

    pub(super) fn load_hot(
        &mut self,
        invocation: InvocationId,
    ) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let file = ExactFileStore::operation_record(self.root.clone(), invocation)?;
        let _guard = self.root.guard()?;
        self.root.audit_entries()?;
        for name in [file.file(), file.stage_file()] {
            if let Some(image) =
                file.read_optional(name, MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES)?
            {
                self.validate(invocation, &image.payload)?;
            }
        }
        let image = file.reconcile(MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES)?;
        if let Some(image) = &image {
            self.validate(invocation, &image.payload)?;
            file.sync_named(file.file())?;
            self.root.sync()?;
        }
        Ok(image.map(|image| image.payload))
    }

    pub(super) fn remove_hot_retired(
        &mut self,
        records: [&[u8]; 2],
        terminal: &[u8],
    ) -> Result<(), CleanFileStoreError> {
        let archive = self
            .terminal_archive
            .as_ref()
            .ok_or(CleanFileStoreError::Corrupt)?
            .clone();
        let ids = archive.ids(terminal)?;
        let saved = archive.load(ids[0])?.ok_or(CleanFileStoreError::Corrupt)?;
        if saved[0] != records[0] || saved[1] != records[1] || saved[2] != terminal {
            return Err(CleanFileStoreError::RequestConflict);
        }
        for (id, expected) in ids.into_iter().zip(records) {
            let Some(current) = self.load_hot(id)? else {
                continue;
            };
            if current != expected {
                return Err(CleanFileStoreError::RequestConflict);
            }
            let file = ExactFileStore::operation_record(self.root.clone(), id)?;
            let _guard = self.root.guard()?;
            self.root.audit_entries()?;
            let named = named_metadata(&self.root.path, file.file())?;
            validate_private_regular_metadata(&named)?;
            let opened = open_read_at(&self.root.directory, &self.root.path, file.file())?;
            validate_opened_file(&opened, &named)?;
            // Re-read exact bytes under the writer guard before unlinking.
            if file
                .read_optional(file.file(), MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES)?
                .is_none_or(|image| image.payload != expected)
                || file
                    .read_optional(
                        file.stage_file(),
                        MAX_NATIVE_AUTHORITY_OPERATION_DISPATCH_BYTES,
                    )?
                    .is_some()
            {
                return Err(CleanFileStoreError::RequestConflict);
            }
            validate_opened_file(&opened, &named_metadata(&self.root.path, file.file())?)?;
            unlink_at(&self.root.directory, &self.root.path, file.file())?;
            self.root.sync()?;
        }
        Ok(())
    }
}
