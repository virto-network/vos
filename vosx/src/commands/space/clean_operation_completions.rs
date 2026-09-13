//! Bounded, append-only signed completion index inside a hardened CSF1 image.
use super::*;
use vos::agent::clean_bootstrap::{
    MAX_NATIVE_OPERATION_COMPLETION_BYTES, MAX_NATIVE_OPERATION_RETIREMENT_BYTES,
    native_operation_completion_invocations, native_operation_retirement_completion,
};
use vos::agent::sdk::{Hash, InvocationId, authority::AuthorityActorTarget};

const MAX_RECORDS: usize =
    vos::agent::authority_operation_coordinator::MAX_AUTHORITY_OPERATION_COORDINATOR_RECORDS;
#[cfg(test)]
const MAX_IMAGE: usize = 40 + MAX_RECORDS * (4 + MAX_NATIVE_OPERATION_COMPLETION_BYTES);

pub(crate) struct CleanNativeAuthorityOperationCompletions {
    file: ExactFileStore,
    authority: AuthorityActorTarget,
    terminal: bool,
}

pub(crate) struct CleanNativeAuthorityOperationRetirements(
    CleanNativeAuthorityOperationCompletions,
);

impl CleanNativeAuthorityOperationRetirements {
    pub(crate) fn open_or_create(
        path: impl AsRef<Path>,
        authority: AuthorityActorTarget,
    ) -> Result<Self, CleanFileStoreError> {
        CleanNativeAuthorityOperationCompletions::open_kind(path.as_ref(), authority, true, true)
            .map(Self)
    }
    pub(crate) fn open_existing(
        path: impl AsRef<Path>,
        authority: AuthorityActorTarget,
    ) -> Result<Self, CleanFileStoreError> {
        CleanNativeAuthorityOperationCompletions::open_kind(path.as_ref(), authority, false, true)
            .map(Self)
    }
    pub(crate) fn load(&self) -> Result<Vec<Vec<u8>>, CleanFileStoreError> {
        self.0.load()
    }
    pub(crate) fn retain(&mut self, certificate: &[u8]) -> Result<(), CleanFileStoreError> {
        self.0.retain(certificate)
    }
}

impl vos::agent::clean_bootstrap::NativeAuthorityOperationRetirementStore
    for CleanNativeAuthorityOperationRetirements
{
    type Error = CleanFileStoreError;
    fn load(&mut self) -> Result<Vec<Vec<u8>>, Self::Error> {
        CleanNativeAuthorityOperationRetirements::load(self)
    }
    fn retain(&mut self, certificate: &[u8]) -> Result<(), Self::Error> {
        CleanNativeAuthorityOperationRetirements::retain(self, certificate)
    }
}

impl vos::agent::clean_bootstrap::NativeAuthorityOperationCompletionStore
    for CleanNativeAuthorityOperationCompletions
{
    type Error = CleanFileStoreError;

    fn load(&mut self) -> Result<Vec<Vec<u8>>, Self::Error> {
        CleanNativeAuthorityOperationCompletions::load(self)
    }

    fn retain(&mut self, certificate: &[u8]) -> Result<(), Self::Error> {
        CleanNativeAuthorityOperationCompletions::retain(self, certificate)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Fixture, stage};
    use super::*;

    // Signature/framing fixture only: these hashes do not claim native
    // execution. Startup must independently match the actual NOD1 pair.
    fn certificate(key: &libp2p::identity::Keypair, number: u16, hash: u8) -> Vec<u8> {
        let mut authorization = [0x41; 32];
        authorization[30..].copy_from_slice(&number.to_be_bytes());
        let mut acknowledgement = [0x42; 32];
        acknowledgement[30..].copy_from_slice(&number.to_be_bytes());
        let fields = [authorization, acknowledgement, [hash; 32], [0x66; 32]].concat();
        let abi = vos::agent::sdk::RUNTIME_ABI_ID.as_bytes();
        let mut message = b"vos/agent/native-operation-completion/v1".to_vec();
        message.extend_from_slice(abi);
        message.extend_from_slice(&fields);
        let signature = key.sign(&message).unwrap();
        let mut bytes = b"NOC1".to_vec();
        bytes.extend_from_slice(abi);
        bytes.extend_from_slice(&fields);
        bytes.extend_from_slice(&64u32.to_le_bytes());
        bytes.extend_from_slice(&signature);
        bytes
    }

    // Signed storage fixture only, not proof of positive native Ack.
    fn terminal(key: &libp2p::identity::Keypair, number: u16, hash: u8) -> Vec<u8> {
        let completion = certificate(key, number, hash);
        terminal_from_completion(key, &completion)
    }

    fn terminal_from_completion(key: &libp2p::identity::Keypair, completion: &[u8]) -> Vec<u8> {
        let abi = vos::agent::sdk::RUNTIME_ABI_ID.as_bytes();
        let mut message = b"vos/agent/native-operation-retirement/v1".to_vec();
        message.extend_from_slice(abi);
        message.extend_from_slice(
            &Hash::digest(
                b"vos/agent/native-operation-retired-completion/v1",
                &[&completion],
            )
            .0,
        );
        let mut bytes = b"NRT1".to_vec();
        bytes.extend_from_slice(abi);
        bytes.extend_from_slice(&(completion.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&completion);
        bytes.extend_from_slice(&64u32.to_le_bytes());
        bytes.extend_from_slice(&key.sign(&message).unwrap());
        bytes
    }

    #[test]
    fn retirement_index_retains_exact_terminal_evidence_and_exclusive_scope() {
        let fixture = Fixture::new("retirement-index");
        let (key, authority, _, _) = crate::commands::space::local_create::tests::fixture();
        let mut store =
            CleanNativeAuthorityOperationRetirements::open_or_create(&fixture.root, authority)
                .unwrap();
        assert!(store.load().unwrap().is_empty());
        let first = terminal(&key, 1, 0x65);
        assert!(store.retain(&certificate(&key, 1, 0x65)).is_err());
        let mut corrupt_completion = certificate(&key, 1, 0x65);
        *corrupt_completion.last_mut().unwrap() ^= 1;
        assert!(
            store
                .retain(&terminal_from_completion(&key, &corrupt_completion))
                .is_err()
        );
        store.retain(&first).unwrap();
        let path = fixture.root.join(StoreRole::OperationRetirements.file());
        let saved = fs::read(&path).unwrap();
        store.retain(&first).unwrap();
        assert_eq!(fs::read(&path).unwrap(), saved);
        assert!(matches!(
            store.retain(&terminal(&key, 1, 0x67)),
            Err(CleanFileStoreError::RequestConflict)
        ));
        let mut corrupt = first.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(store.retain(&corrupt).is_err());
        assert!(matches!(
            CleanNativeAuthorityOperationRetirements::open_existing(&fixture.root, authority),
            Err(CleanFileStoreError::Busy)
        ));
        drop(store);
        let store =
            CleanNativeAuthorityOperationRetirements::open_existing(&fixture.root, authority)
                .unwrap();
        assert_eq!(store.load().unwrap(), vec![first]);
        drop(store);
        assert!(
            CleanNativeAuthorityOperationCompletions::open_existing(&fixture.root, authority)
                .is_err()
        );
        let mut wrong = authority;
        wrong.system_agent.0[0] ^= 1;
        assert!(
            CleanNativeAuthorityOperationRetirements::open_existing(&fixture.root, wrong).is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), saved);
        let absent = fixture.parent.join("absent-terminal");
        assert!(
            CleanNativeAuthorityOperationRetirements::open_existing(&absent, authority).is_err()
        );
        assert!(!absent.exists());
    }

    #[test]
    fn retirement_index_recovers_append_and_preserves_conflicting_or_malformed_stages() {
        let (key, authority, _, _) = crate::commands::space::local_create::tests::fixture();
        let first = terminal(&key, 1, 0x65);
        let second = terminal(&key, 2, 0x65);
        for mode in 0..6 {
            let fixture = Fixture::new("retirement-stage");
            let mut store =
                CleanNativeAuthorityOperationRetirements::open_or_create(&fixture.root, authority)
                    .unwrap();
            store.retain(&first).unwrap();
            let predecessor = store
                .0
                .file
                .read_optional(store.0.file.file(), store.0.maximum_image())
                .unwrap()
                .unwrap();
            let records = match mode {
                0 => vec![first.clone(), second.clone()],
                1 => vec![],
                2 => vec![terminal(&key, 1, 0x67)],
                3 => vec![first.clone(), first.clone()],
                4 => vec![certificate(&key, 1, 0x65)],
                _ => vec![first.clone()],
            };
            let mut payload = store.0.encode(&records).unwrap();
            if mode == 5 {
                payload.push(0);
            }
            stage(&store.0.file, Some(predecessor.commitment()), &payload);
            let path = fixture.root.join(store.0.file.file());
            let staged = fixture.root.join(store.0.file.stage_file());
            let saved = fs::read(&path).unwrap();
            let saved_stage = fs::read(&staged).unwrap();
            drop(store);
            let reopened =
                CleanNativeAuthorityOperationRetirements::open_existing(&fixture.root, authority);
            if mode == 0 {
                assert_eq!(reopened.unwrap().load().unwrap(), records);
                assert!(!staged.exists());
            } else {
                assert!(reopened.is_err());
                assert_eq!(fs::read(&path).unwrap(), saved);
                assert_eq!(fs::read(&staged).unwrap(), saved_stage);
            }
        }
    }

    #[test]
    fn retirement_index_enforces_capacity_without_eviction() {
        let fixture = Fixture::new("retirement-capacity");
        let (key, authority, _, _) = crate::commands::space::local_create::tests::fixture();
        let mut store =
            CleanNativeAuthorityOperationRetirements::open_or_create(&fixture.root, authority)
                .unwrap();
        assert_eq!(
            store.0.maximum_image(),
            StoreRole::OperationRetirements.maximum_bytes()
        );
        let records: Vec<_> = (0..MAX_RECORDS)
            .map(|i| terminal(&key, i as u16, 0x65))
            .collect();
        stage(&store.0.file, None, &store.0.encode(&records).unwrap());
        assert_eq!(store.load().unwrap(), records);
        let path = fixture.root.join(store.0.file.file());
        let saved = fs::read(&path).unwrap();
        assert!(matches!(
            store.retain(&terminal(&key, MAX_RECORDS as u16, 0x65)),
            Err(CleanFileStoreError::Oversized)
        ));
        assert_eq!(fs::read(&path).unwrap(), saved);
        assert_eq!(store.load().unwrap(), records);
    }

    #[test]
    fn completion_index_retains_exact_certificates_and_exclusive_scope() {
        let fixture = Fixture::new("completion-index");
        let (key, authority, _, _) = crate::commands::space::local_create::tests::fixture();
        let mut store =
            CleanNativeAuthorityOperationCompletions::open_or_create(&fixture.root, authority)
                .unwrap();
        assert!(store.load().unwrap().is_empty());
        let first = certificate(&key, 1, 0x65);
        store.retain(&first).unwrap();
        let original = fs::read(fixture.root.join(store.file.file())).unwrap();
        store.retain(&first).unwrap();
        assert_eq!(
            fs::read(fixture.root.join(store.file.file())).unwrap(),
            original
        );
        assert!(matches!(
            store.retain(&certificate(&key, 1, 0x67)),
            Err(CleanFileStoreError::RequestConflict)
        ));
        let mut bad = first.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(store.retain(&bad).is_err());
        assert_eq!(store.load().unwrap(), vec![first.clone()]);
        assert!(matches!(
            CleanNativeAuthorityOperationCompletions::open_existing(&fixture.root, authority),
            Err(CleanFileStoreError::Busy)
        ));
        drop(store);
        let store =
            CleanNativeAuthorityOperationCompletions::open_existing(&fixture.root, authority)
                .unwrap();
        assert_eq!(store.load().unwrap(), vec![first]);
        drop(store);
        let mut wrong = authority;
        wrong.system_agent.0[0] ^= 1;
        assert!(
            CleanNativeAuthorityOperationCompletions::open_existing(&fixture.root, wrong).is_err()
        );
        assert_eq!(
            fs::read(fixture.root.join(StoreRole::OperationCompletions.file())).unwrap(),
            original
        );
        let absent = fixture.parent.join("absent");
        assert!(
            CleanNativeAuthorityOperationCompletions::open_existing(&absent, authority).is_err()
        );
        assert!(!absent.exists());
    }

    #[test]
    fn completion_index_recovers_append_but_preserves_removal_and_replacement_stages() {
        let (key, authority, _, _) = crate::commands::space::local_create::tests::fixture();
        let first = certificate(&key, 1, 0x65);
        let second = certificate(&key, 2, 0x65);
        for mode in 0..3 {
            let fixture = Fixture::new("completion-stage");
            let mut store =
                CleanNativeAuthorityOperationCompletions::open_or_create(&fixture.root, authority)
                    .unwrap();
            store.retain(&first).unwrap();
            let predecessor = store
                .file
                .read_optional(store.file.file(), MAX_IMAGE)
                .unwrap()
                .unwrap();
            let records = match mode {
                0 => vec![first.clone(), second.clone()],
                1 => vec![],
                _ => vec![certificate(&key, 1, 0x67)],
            };
            let payload = store.encode(&records).unwrap();
            stage(&store.file, Some(predecessor.commitment()), &payload);
            let stage_path = fixture.root.join(store.file.stage_file());
            let saved_stage = fs::read(&stage_path).unwrap();
            let saved = fs::read(fixture.root.join(store.file.file())).unwrap();
            drop(store);
            let reopened =
                CleanNativeAuthorityOperationCompletions::open_existing(&fixture.root, authority);
            if mode == 0 {
                assert_eq!(reopened.unwrap().load().unwrap(), records);
                assert!(!stage_path.exists());
            } else {
                assert!(reopened.is_err());
                assert_eq!(fs::read(&stage_path).unwrap(), saved_stage);
                assert_eq!(
                    fs::read(fixture.root.join(StoreRole::OperationCompletions.file())).unwrap(),
                    saved
                );
            }
        }
    }

    #[test]
    fn completion_index_rejects_malformed_stages_without_publication() {
        let (key, authority, _, _) = crate::commands::space::local_create::tests::fixture();
        let first = certificate(&key, 1, 0x65);
        let second = certificate(&key, 2, 0x65);
        for mode in 0..6 {
            let fixture = Fixture::new("completion-malformed");
            let store =
                CleanNativeAuthorityOperationCompletions::open_or_create(&fixture.root, authority)
                    .unwrap();
            let mut payload = match mode {
                0 => store.encode(&[second.clone(), first.clone()]).unwrap(),
                1 => store.encode(&[first.clone(), first.clone()]).unwrap(),
                _ => store.encode(&[first.clone()]).unwrap(),
            };
            match mode {
                2 => payload.push(0),
                3 => {
                    payload.pop();
                }
                4 => *payload.last_mut().unwrap() ^= 1,
                5 => payload[40..44].copy_from_slice(&513u32.to_le_bytes()),
                _ => {}
            }
            stage(&store.file, None, &payload);
            let stage_path = fixture.root.join(store.file.stage_file());
            let saved = fs::read(&stage_path).unwrap();
            drop(store);
            assert!(
                CleanNativeAuthorityOperationCompletions::open_existing(&fixture.root, authority)
                    .is_err()
            );
            assert_eq!(fs::read(stage_path).unwrap(), saved);
            assert!(
                !fixture
                    .root
                    .join(StoreRole::OperationCompletions.file())
                    .exists()
            );
        }
    }

    #[test]
    fn completion_index_enforces_count_bound_without_eviction() {
        assert_eq!(StoreRole::OperationCompletions.maximum_bytes(), MAX_IMAGE);
        let fixture = Fixture::new("completion-capacity");
        let (key, authority, _, _) = crate::commands::space::local_create::tests::fixture();
        let mut store =
            CleanNativeAuthorityOperationCompletions::open_or_create(&fixture.root, authority)
                .unwrap();
        let records: Vec<_> = (0..MAX_RECORDS)
            .map(|index| certificate(&key, index as u16, 0x65))
            .collect();
        stage(&store.file, None, &store.encode(&records).unwrap());
        assert_eq!(store.load().unwrap(), records);
        let saved = fs::read(fixture.root.join(store.file.file())).unwrap();
        assert!(matches!(
            store.retain(&certificate(&key, MAX_RECORDS as u16, 0x65)),
            Err(CleanFileStoreError::Oversized)
        ));
        assert_eq!(
            fs::read(fixture.root.join(store.file.file())).unwrap(),
            saved
        );
        assert_eq!(store.load().unwrap(), records);
    }
}

impl CleanNativeAuthorityOperationCompletions {
    pub(crate) fn open_or_create(
        path: impl AsRef<Path>,
        authority: AuthorityActorTarget,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open(path.as_ref(), authority, true)
    }

    pub(crate) fn open_existing(
        path: impl AsRef<Path>,
        authority: AuthorityActorTarget,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open(path.as_ref(), authority, false)
    }

    fn open(
        path: &Path,
        authority: AuthorityActorTarget,
        create: bool,
    ) -> Result<Self, CleanFileStoreError> {
        Self::open_kind(path, authority, create, false)
    }

    fn open_kind(
        path: &Path,
        authority: AuthorityActorTarget,
        create: bool,
        terminal: bool,
    ) -> Result<Self, CleanFileStoreError> {
        if !authority.is_valid() {
            return Err(CleanFileStoreError::InvalidPath);
        }
        let role = if terminal {
            StoreRole::OperationRetirements
        } else {
            StoreRole::OperationCompletions
        };
        const COMPLETION_ENTRIES: &[&str] = &[
            LOCK_FILE,
            StoreRole::OperationCompletions.file(),
            StoreRole::OperationCompletions.stage_file(),
        ];
        const RETIREMENT_ENTRIES: &[&str] = &[
            LOCK_FILE,
            StoreRole::OperationRetirements.file(),
            StoreRole::OperationRetirements.stage_file(),
        ];
        let entries = if terminal {
            RETIREMENT_ENTRIES
        } else {
            COMPLETION_ENTRIES
        };
        let root = Arc::new(StoreRoot::open_with_entries_mode(path, entries, create)?);
        let store = Self {
            file: ExactFileStore::new(root, role),
            authority,
            terminal,
        };
        store.load()?;
        Ok(store)
    }

    fn scope(&self) -> Hash {
        Hash::digest(
            if self.terminal {
                b"vos/agent/native-operation-retirement-index/v1"
            } else {
                b"vos/agent/native-operation-completion-index/v1"
            },
            &[
                &self.authority.space.0,
                &self.authority.system_agent.0,
                &self.authority.system_runtime_deployment.0,
                &self.authority.binding.commitment().0,
            ],
        )
    }

    fn ids(&self, bytes: &[u8]) -> Result<[InvocationId; 2], CleanFileStoreError> {
        let completion;
        let bytes = if self.terminal {
            completion =
                native_operation_retirement_completion(&self.authority.binding.public_key, bytes)
                    .ok_or(CleanFileStoreError::Corrupt)?;
            completion.as_slice()
        } else {
            bytes
        };
        native_operation_completion_invocations(&self.authority.binding.public_key, bytes)
            .ok_or(CleanFileStoreError::Corrupt)
    }

    fn maximum_record(&self) -> usize {
        if self.terminal {
            MAX_NATIVE_OPERATION_RETIREMENT_BYTES
        } else {
            MAX_NATIVE_OPERATION_COMPLETION_BYTES
        }
    }
    fn maximum_image(&self) -> usize {
        40 + MAX_RECORDS * (4 + self.maximum_record())
    }
    fn magic(&self) -> &[u8; 4] {
        if self.terminal { b"NRI1" } else { b"NCI1" }
    }

    fn encode(&self, records: &[Vec<u8>]) -> Result<Vec<u8>, CleanFileStoreError> {
        if records.len() > MAX_RECORDS {
            return Err(CleanFileStoreError::Oversized);
        }
        let mut bytes = self.magic().to_vec();
        bytes.extend_from_slice(&self.scope().0);
        bytes.extend_from_slice(&(records.len() as u32).to_le_bytes());
        for record in records {
            if record.len() > self.maximum_record() {
                return Err(CleanFileStoreError::Oversized);
            }
            bytes.extend_from_slice(&(record.len() as u32).to_le_bytes());
            bytes.extend_from_slice(record);
        }
        Ok(bytes)
    }

    fn decode(&self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, CleanFileStoreError> {
        if bytes.len() > self.maximum_image() {
            return Err(CleanFileStoreError::Oversized);
        }
        if bytes.len() < 40 || &bytes[..4] != self.magic() || bytes[4..36] != self.scope().0 {
            return Err(CleanFileStoreError::Corrupt);
        }
        let count = u32::from_le_bytes(bytes[36..40].try_into().unwrap()) as usize;
        if count > MAX_RECORDS {
            return Err(CleanFileStoreError::Oversized);
        }
        let mut cursor = 40;
        let mut records = Vec::new();
        let mut previous = None;
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..count {
            let size = bytes
                .get(cursor..cursor + 4)
                .ok_or(CleanFileStoreError::Corrupt)?;
            cursor += 4;
            let size = u32::from_le_bytes(size.try_into().unwrap()) as usize;
            if size > self.maximum_record() {
                return Err(CleanFileStoreError::Oversized);
            }
            let record = bytes
                .get(cursor..cursor + size)
                .ok_or(CleanFileStoreError::Corrupt)?;
            cursor += size;
            let [authorization, acknowledgement] = self.ids(record)?;
            if previous.is_some_and(|last| last >= authorization)
                || !seen.insert(authorization)
                || !seen.insert(acknowledgement)
            {
                return Err(CleanFileStoreError::Corrupt);
            }
            previous = Some(authorization);
            records.push(record.to_vec());
        }
        if cursor != bytes.len() {
            return Err(CleanFileStoreError::Corrupt);
        }
        Ok(records)
    }

    /// Full NOD1 scope/linkage is independently checked by native startup before
    /// any returned certificate is used. This layer validates signatures/index.
    pub(crate) fn load(&self) -> Result<Vec<Vec<u8>>, CleanFileStoreError> {
        let _guard = self.file.root.guard()?;
        self.file.root.audit_entries()?;
        let canonical = self
            .file
            .read_optional(self.file.file(), self.maximum_image())?;
        let staged = self
            .file
            .read_optional(self.file.stage_file(), self.maximum_image())?;
        let current = canonical
            .as_ref()
            .map(|image| self.decode(&image.payload))
            .transpose()?;
        let next = staged
            .as_ref()
            .map(|image| self.decode(&image.payload))
            .transpose()?;
        if let (Some(current), Some(next)) = (&current, &next) {
            if next.len() < current.len()
                || next.len() > current.len() + 1
                || current.iter().any(|record| !next.contains(record))
            {
                return Err(CleanFileStoreError::RequestConflict);
            }
        }
        let image = self.file.reconcile(self.maximum_image())?;
        match image {
            Some(image) => {
                let records = self.decode(&image.payload)?;
                self.file.sync_named(self.file.file())?;
                self.file.root.sync()?;
                Ok(records)
            }
            None => Ok(Vec::new()),
        }
    }

    pub(crate) fn retain(&mut self, certificate: &[u8]) -> Result<(), CleanFileStoreError> {
        let ids = self.ids(certificate)?;
        let mut records = self.load()?;
        for current in &records {
            if current == certificate {
                return self.file.commit(&self.encode(&records)?);
            }
            if self.ids(current)?.iter().any(|id| ids.contains(id)) {
                return Err(CleanFileStoreError::RequestConflict);
            }
        }
        if records.len() == MAX_RECORDS {
            return Err(CleanFileStoreError::Oversized);
        }
        records.push(certificate.to_vec());
        records.sort_unstable_by_key(|record| self.ids(record).expect("validated certificate")[0]);
        self.file.commit(&self.encode(&records)?)
    }
}
