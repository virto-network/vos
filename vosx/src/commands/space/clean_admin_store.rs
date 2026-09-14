//! Role-separated, immutable admin evidence using hardened CSF1 storage.
#[cfg(test)]
#[path = "clean_admin_store_tests.rs"]
mod tests;
use super::*;
use vos::agent::clean_bootstrap::{
    NativeAuthorityAdminJournalStore, NativeAuthorityAdminTerminalStore,
    native_admin_record_matches, native_admin_terminal_matches,
};
use vos::agent::sdk::{InvocationId, authority::AuthorityActorTarget};

#[derive(Clone)]
struct Records {
    root: Arc<StoreRoot>,
    authority: AuthorityActorTarget,
    role: StoreRole,
    source: Option<Arc<Records>>,
}

impl Records {
    fn open(
        path: &Path,
        authority: AuthorityActorTarget,
        role: StoreRole,
        source: Option<Arc<Records>>,
        create: bool,
    ) -> Result<Self, CleanFileStoreError> {
        if !authority.is_valid() {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let records = Self {
            root: Arc::new(StoreRoot::open_namespace(path, &[LOCK_FILE], create, true)?),
            authority,
            role,
            source,
        };
        for id in records.discover()? {
            records.load(id)?.ok_or(CleanFileStoreError::Corrupt)?;
        }
        Ok(records)
    }

    fn discover(&self) -> Result<Vec<InvocationId>, CleanFileStoreError> {
        self.root.audit_entries()?;
        let scan = PathBuf::from(format!("/proc/self/fd/{}", self.root.directory.as_raw_fd()));
        let mut ids = std::collections::BTreeSet::new();
        for entry in fs::read_dir(scan)? {
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| CleanFileStoreError::UnexpectedResidue)?;
            if name == LOCK_FILE {
                continue;
            }
            ids.insert(operation_record_name(&name).ok_or(CleanFileStoreError::UnexpectedResidue)?);
            if ids.len() > MAX_OPERATION_JOURNAL_RECORDS {
                return Err(CleanFileStoreError::Oversized);
            }
        }
        self.root.audit_entries()?;
        Ok(ids.into_iter().collect())
    }

    fn validate(&self, id: InvocationId, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        if bytes.len() > self.role.maximum_bytes() {
            return Err(CleanFileStoreError::Oversized);
        }
        let valid = if self.role == StoreRole::AdminDispatch {
            native_admin_record_matches(self.authority, id, bytes)
        } else {
            let dispatch = self
                .source
                .as_ref()
                .ok_or(CleanFileStoreError::Corrupt)?
                .load(id)?
                .ok_or(CleanFileStoreError::Corrupt)?;
            native_admin_terminal_matches(
                self.authority,
                id,
                &dispatch,
                self.role == StoreRole::AdminRetirement,
                bytes,
            )
        };
        if valid {
            Ok(())
        } else {
            Err(CleanFileStoreError::Corrupt)
        }
    }

    fn file(&self, id: InvocationId) -> Result<ExactFileStore, CleanFileStoreError> {
        ExactFileStore::invocation_record(self.root.clone(), id, self.role)
    }

    fn load(&self, id: InvocationId) -> Result<Option<Vec<u8>>, CleanFileStoreError> {
        let file = self.file(id)?;
        let _guard = self.root.guard()?;
        self.root.audit_entries()?;
        // Validate both candidates, including source binding, before publishing
        // any stage. An orphan terminal record is corruption, not completion.
        for name in [file.file(), file.stage_file()] {
            if let Some(image) = file.read_optional(name, self.role.maximum_bytes())? {
                self.validate(id, &image.payload)?;
            }
        }
        let image = file.reconcile(self.role.maximum_bytes())?;
        if image.is_some() {
            file.sync_named(file.file())?;
            self.root.sync()?;
        }
        Ok(image.map(|image| image.payload))
    }

    fn retain(&self, id: InvocationId, bytes: &[u8]) -> Result<(), CleanFileStoreError> {
        self.validate(id, bytes)?;
        let prior = self.load(id)?;
        if prior.as_deref().is_some_and(|old| old != bytes) {
            return Err(CleanFileStoreError::RequestConflict);
        }
        if prior.is_none() && self.discover()?.len() == MAX_OPERATION_JOURNAL_RECORDS {
            return Err(CleanFileStoreError::Oversized);
        }
        self.file(id)?.commit_with_replacement(bytes, false)
    }
}

pub(crate) struct CleanNativeAuthorityAdminJournal(Arc<Records>);
pub(crate) struct CleanNativeAuthorityAdminTerminals {
    observed: Records,
    retired: Records,
}
pub(crate) struct CleanNativeAuthorityAdminStores {
    pub(crate) journal: CleanNativeAuthorityAdminJournal,
    pub(crate) terminals: CleanNativeAuthorityAdminTerminals,
}
impl CleanNativeAuthorityAdminStores {
    /// All paths are dedicated sibling namespaces selected by daemon setup.
    /// Their existing private parent must already be established by the caller.
    pub(crate) fn open(
        dispatch: &Path,
        observed: &Path,
        retired: &Path,
        authority: AuthorityActorTarget,
        create: bool,
    ) -> Result<Self, CleanFileStoreError> {
        let source = Arc::new(Records::open(
            dispatch,
            authority,
            StoreRole::AdminDispatch,
            None,
            create,
        )?);
        let observed = Records::open(
            observed,
            authority,
            StoreRole::AdminResult,
            Some(source.clone()),
            create,
        )?;
        let retired = Records::open(
            retired,
            authority,
            StoreRole::AdminRetirement,
            Some(source.clone()),
            create,
        )?;
        Ok(Self {
            journal: CleanNativeAuthorityAdminJournal(source),
            terminals: CleanNativeAuthorityAdminTerminals { observed, retired },
        })
    }
}
impl CleanNativeAuthorityAdminJournal {
    pub(crate) fn discover(&self) -> Result<Vec<InvocationId>, CleanFileStoreError> {
        self.0.discover()
    }
}
impl NativeAuthorityAdminJournalStore for CleanNativeAuthorityAdminJournal {
    type Error = CleanFileStoreError;
    fn load(&mut self, id: InvocationId) -> Result<Option<Vec<u8>>, Self::Error> {
        self.0.load(id)
    }
    fn retain(&mut self, id: InvocationId, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.retain(id, bytes)
    }
}
impl NativeAuthorityAdminTerminalStore for CleanNativeAuthorityAdminTerminals {
    type Error = CleanFileStoreError;
    fn load(&mut self, id: InvocationId, retired: bool) -> Result<Option<Vec<u8>>, Self::Error> {
        if retired {
            self.retired.load(id)
        } else {
            self.observed.load(id)
        }
    }
    fn retain(&mut self, id: InvocationId, retired: bool, bytes: &[u8]) -> Result<(), Self::Error> {
        if retired {
            self.retired.retain(id, bytes)
        } else {
            self.observed.retain(id, bytes)
        }
    }
}
