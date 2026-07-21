//! Atomic local JAM storage host for the v2 conformance runtime.
//!
//! This module implements only the physical storage and preimage protocol
//! calls used by the canonical service PVM. It deliberately does not decode or
//! apply [`super::TransitionV2`]: all validation and mutation semantics remain
//! guest-owned at the IC-5 Accumulate entry.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use javm::kernel::InvocationKernel;

use crate::attestation::AttestationProofHostV2;

use super::wire::{DecodeError, Decoder, Encoder};
use super::{
    AccumulateProtocolHostV2, AccumulateTransactionV2, BlobRefV2, ProgramId,
    ProofVerificationRequestV2, PublicationRecordV2, ReceiptVerificationRequestV2,
    ServiceGenesisV2, ServicePvmErrorV2, ServiceStateTreeV2, StateKeyV2, StateTreeStore,
    StoreHeaderV2, StoreOpenError, V2Wire,
};

/// Recoverable committed image of a local v2 service account.
///
/// Rows include the guest-owned header, authenticated state nodes, receipts,
/// deduplication records, and CRDT DAG nodes. Blobs contain exact bytes keyed
/// by the canonical VOS blob hash. Its strict v2 wire is the crash-safe image
/// a host persists; it contains no in-flight transaction or verifier policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalJamStoreSnapshotV2 {
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    blobs: BTreeMap<[u8; 32], Vec<u8>>,
    programs: BTreeMap<[u8; 32], Vec<u8>>,
    commit_sequence: u64,
}

impl LocalJamStoreSnapshotV2 {
    /// Compare consensus-visible rows and blobs while ignoring the host-local
    /// count of completed transaction boundaries.
    pub fn same_service_state(&self, other: &Self) -> bool {
        self.rows == other.rows && self.blobs == other.blobs && self.programs == other.programs
    }
}

impl V2Wire for LocalJamStoreSnapshotV2 {
    const MAGIC: [u8; 4] = *b"VSS2";

    fn encode_body(&self, out: &mut Vec<u8>) {
        let mut encoder = Encoder(out);
        encoder.u64(self.commit_sequence);
        encoder.u32(self.rows.len() as u32);
        for (key, value) in &self.rows {
            encoder.bytes(key);
            encoder.bytes(value);
        }
        encoder.u32(self.blobs.len() as u32);
        for (hash, bytes) in &self.blobs {
            encoder.fixed(hash);
            encoder.bytes(bytes);
        }
        encoder.u32(self.programs.len() as u32);
        for (program, pvm) in &self.programs {
            encoder.fixed(program);
            encoder.bytes(pvm);
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let commit_sequence = decoder.u64()?;
        let rows = decode_byte_map(decoder)?;
        let blobs = decode_content_map(decoder, |key, bytes| {
            BlobRefV2::of_bytes(bytes).hash.0 == *key
        })?;
        let programs =
            decode_content_map(decoder, |key, bytes| ProgramId::of_pvm(bytes).0 == *key)?;
        if rows.is_empty() != (commit_sequence == 0) {
            return Err(DecodeError::NonCanonical);
        }
        if !rows.is_empty() {
            let header = rows
                .get(super::header_storage_key())
                .ok_or(DecodeError::NonCanonical)?;
            StoreHeaderV2::open(header).map_err(|_| DecodeError::NonCanonical)?;
        }
        Ok(Self {
            rows,
            blobs,
            programs,
            commit_sequence,
        })
    }
}

fn decode_byte_map(decoder: &mut Decoder<'_>) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, DecodeError> {
    let entries = decoder.list(|decoder| Ok((decoder.bytes()?, decoder.bytes()?)))?;
    let mut result = BTreeMap::new();
    let mut previous: Option<Vec<u8>> = None;
    for (key, value) in entries {
        if key.is_empty()
            || value.is_empty()
            || previous.as_ref().is_some_and(|previous| previous >= &key)
        {
            return Err(DecodeError::NonCanonical);
        }
        previous = Some(key.clone());
        result.insert(key, value);
    }
    Ok(result)
}

fn decode_content_map(
    decoder: &mut Decoder<'_>,
    valid: impl Fn(&[u8; 32], &[u8]) -> bool,
) -> Result<BTreeMap<[u8; 32], Vec<u8>>, DecodeError> {
    let entries = decoder.list(|decoder| Ok((decoder.fixed()?, decoder.bytes()?)))?;
    let mut result = BTreeMap::new();
    let mut previous = None;
    for (key, bytes) in entries {
        if previous.as_ref().is_some_and(|previous| previous >= &key) || !valid(&key, &bytes) {
            return Err(DecodeError::NonCanonical);
        }
        previous = Some(key);
        result.insert(key, bytes);
    }
    Ok(result)
}

/// Durable sink for one complete, canonical service-account image.
///
/// `commit` must not return success until the image is recoverable after a
/// process restart. A local filesystem implementation can use atomic rename;
/// a Raft implementation can block until the bytes have reached a quorum.
/// The service host never exposes the candidate image before this boundary
/// succeeds.
pub trait CommittedImageStoreV2 {
    type Error;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error>;
}

/// Process-local committed-image sink for one-shot hosts and conformance
/// tests. It exercises the same durable-host transaction ordering without
/// claiming crash persistence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryCommittedImageStoreV2 {
    image: Option<Vec<u8>>,
}

impl MemoryCommittedImageStoreV2 {
    pub fn image(&self) -> Option<&[u8]> {
        self.image.as_deref()
    }
}

impl CommittedImageStoreV2 for MemoryCommittedImageStoreV2 {
    type Error = core::convert::Infallible;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.image.clone())
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        self.image = Some(image.to_vec());
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceImageInstallErrorV2 {
    InvalidSnapshot,
    ServiceMismatch,
    PersistenceRejected,
}

/// Read and atomically replace the consensus-visible image owned by a
/// physical service host. Raft catch-up uses this boundary for an installed
/// snapshot; it never reconstructs actor state from native commands.
pub trait CommittedServiceImageHostV2 {
    fn committed_service_image(&self) -> Vec<u8>;

    fn install_committed_service_image(
        &mut self,
        image: &[u8],
    ) -> Result<(), ServiceImageInstallErrorV2>;
}

#[derive(Debug)]
pub enum DurableStoreOpenErrorV2<E> {
    Backend(E),
    InvalidSnapshot(DecodeError),
}

impl<E: core::fmt::Debug> core::fmt::Display for DurableStoreOpenErrorV2<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot open durable VOS v2 service state: {self:?}")
    }
}

impl<E: core::fmt::Debug> core::error::Error for DurableStoreOpenErrorV2<E> {}

/// Atomic filesystem sink for canonical service-account images.
///
/// The next image is flushed to a sibling temporary file, renamed over the
/// committed path, and followed by a parent-directory sync. One store path is
/// owned by one service writer; Raft-backed services use a quorum sink instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileCommittedImageStoreV2 {
    path: PathBuf,
}

impl FileCommittedImageStoreV2 {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn temporary_path(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".v2-next");
        self.path.with_file_name(name)
    }
}

impl CommittedImageStoreV2 for FileCommittedImageStoreV2 {
    type Error = std::io::Error;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        use std::io::Write;

        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let temporary = self.temporary_path();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(image)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &self.path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalStoreReadErrorV2 {
    InvalidHeader(StoreOpenError),
    CorruptStateTree,
    CorruptPublication,
}

impl core::fmt::Display for LocalStoreReadErrorV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot read committed VOS v2 service state: {self:?}")
    }
}

impl core::error::Error for LocalStoreReadErrorV2 {}

/// In-memory implementation of the JAM storage boundary used by the local
/// runtime and conformance tests.
///
/// [`AccumulateProtocolHostV2::begin`] clones the committed image. IC-5 reads
/// and writes only that isolated image, and [`AccumulateProtocolHostV2::commit`]
/// swaps it into visibility atomically. Dropping a transaction therefore
/// discards every staged row and blob.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalJamStoreV2 {
    committed: LocalJamStoreSnapshotV2,
    proof_allowlist: BTreeSet<super::Hash>,
    install_allowlist: BTreeSet<super::Hash>,
    receipt_allowlist: BTreeSet<super::Hash>,
}

/// JAM storage host whose committed image is made durable before IC-5 returns.
///
/// Host policy (proof, installation, and receipt verifier configuration)
/// remains process-local. Only consensus-visible service state crosses the
/// [`CommittedImageStoreV2`] boundary.
pub struct DurableJamStoreV2<B> {
    local: LocalJamStoreV2,
    backend: B,
}

impl<B: CommittedImageStoreV2> DurableJamStoreV2<B> {
    pub fn open(mut backend: B) -> Result<Self, DurableStoreOpenErrorV2<B::Error>> {
        let local = match backend.load().map_err(DurableStoreOpenErrorV2::Backend)? {
            Some(bytes) => LocalJamStoreV2::from_snapshot_bytes(&bytes)
                .map_err(DurableStoreOpenErrorV2::InvalidSnapshot)?,
            None => LocalJamStoreV2::new(),
        };
        Ok(Self { local, backend })
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn into_parts(self) -> (LocalJamStoreV2, B) {
        (self.local, self.backend)
    }
}

impl<B> Deref for DurableJamStoreV2<B> {
    type Target = LocalJamStoreV2;

    fn deref(&self) -> &Self::Target {
        &self.local
    }
}

impl<B> DerefMut for DurableJamStoreV2<B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.local
    }
}

impl LocalJamStoreV2 {
    pub const fn new() -> Self {
        Self {
            committed: LocalJamStoreSnapshotV2 {
                rows: BTreeMap::new(),
                blobs: BTreeMap::new(),
                programs: BTreeMap::new(),
                commit_sequence: 0,
            },
            proof_allowlist: BTreeSet::new(),
            install_allowlist: BTreeSet::new(),
            receipt_allowlist: BTreeSet::new(),
        }
    }

    /// Restore exactly one previously committed service-account image.
    pub fn from_snapshot(snapshot: LocalJamStoreSnapshotV2) -> Self {
        Self {
            committed: snapshot,
            proof_allowlist: BTreeSet::new(),
            install_allowlist: BTreeSet::new(),
            receipt_allowlist: BTreeSet::new(),
        }
    }

    /// Restore one canonical committed image read from durable storage.
    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        LocalJamStoreSnapshotV2::decode(bytes).map(Self::from_snapshot)
    }

    fn validate_replacement(
        &self,
        image: &[u8],
    ) -> Result<LocalJamStoreSnapshotV2, ServiceImageInstallErrorV2> {
        let replacement = LocalJamStoreSnapshotV2::decode(image)
            .map_err(|_| ServiceImageInstallErrorV2::InvalidSnapshot)?;
        let replacement_header = replacement
            .rows
            .get(super::header_storage_key())
            .map(|bytes| StoreHeaderV2::open(bytes))
            .transpose()
            .map_err(|_| ServiceImageInstallErrorV2::InvalidSnapshot)?;
        let current_header = self
            .header()
            .map_err(|_| ServiceImageInstallErrorV2::InvalidSnapshot)?;
        if let Some(current) = current_header
            && replacement_header.as_ref().is_none_or(|next| {
                next.service != current.service || next.consistency != current.consistency
            })
        {
            return Err(ServiceImageInstallErrorV2::ServiceMismatch);
        }
        Ok(replacement)
    }

    /// Capture only committed state. An active Accumulate transaction is owned
    /// by the service invocation and cannot be observed through this object.
    pub fn snapshot(&self) -> LocalJamStoreSnapshotV2 {
        self.committed.clone()
    }

    /// Canonical crash-recovery image. Verifier/install allowlists are host
    /// policy and deliberately remain outside persisted service state.
    pub fn snapshot_bytes(&self) -> Vec<u8> {
        self.committed.encode()
    }

    pub const fn commit_sequence(&self) -> u64 {
        self.committed.commit_sequence
    }

    pub fn row_count(&self) -> usize {
        self.committed.rows.len()
    }

    pub fn blob_count(&self) -> usize {
        self.committed.blobs.len()
    }

    pub fn program_count(&self) -> usize {
        self.committed.programs.len()
    }

    pub fn row(&self, key: &[u8]) -> Option<&[u8]> {
        self.committed.rows.get(key).map(Vec::as_slice)
    }

    pub fn blob(&self, reference: &BlobRefV2) -> Option<&[u8]> {
        self.committed
            .blobs
            .get(&reference.hash.0)
            .filter(|bytes| reference.matches(bytes))
            .map(Vec::as_slice)
    }

    pub fn program(&self, program: ProgramId) -> Option<&[u8]> {
        self.committed
            .programs
            .get(&program.0)
            .filter(|bytes| ProgramId::of_pvm(bytes) == program)
            .map(Vec::as_slice)
    }

    pub fn header(&self) -> Result<Option<StoreHeaderV2>, LocalStoreReadErrorV2> {
        self.row(super::header_storage_key())
            .map(StoreHeaderV2::open)
            .transpose()
            .map_err(LocalStoreReadErrorV2::InvalidHeader)
    }

    /// Read one authenticated logical row at a committed root. This private
    /// adapter exposes no write method to callers; it exists so scheduling can
    /// derive imports without adding a mutable host-side service model.
    pub fn state_row(
        &self,
        root: super::Hash,
        key: &StateKeyV2,
    ) -> Result<Option<Vec<u8>>, LocalStoreReadErrorV2> {
        let mut view = CommittedRows(&self.committed.rows);
        ServiceStateTreeV2::new(&mut view, root)
            .get(key)
            .map_err(|_| LocalStoreReadErrorV2::CorruptStateTree)
    }

    /// Recover committed effects which have not yet been acknowledged through
    /// guest Accumulate. Canonical row order is stable across restarts.
    pub fn pending_publications(&self) -> Result<Vec<PublicationRecordV2>, LocalStoreReadErrorV2> {
        let prefix = super::storage::publication_storage_prefix();
        self.committed
            .rows
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, bytes)| {
                let publication = PublicationRecordV2::decode(bytes)
                    .map_err(|_| LocalStoreReadErrorV2::CorruptPublication)?;
                if super::publication_storage_key(publication.input).as_slice() != key.as_slice() {
                    return Err(LocalStoreReadErrorV2::CorruptPublication);
                }
                Ok(publication)
            })
            .collect()
    }

    /// Make an installation input available to guest Accumulate. This is a
    /// content-addressed import operation, not a service-state mutation.
    pub fn import_blob(&mut self, bytes: Vec<u8>) -> BlobRefV2 {
        let reference = BlobRefV2::of_bytes(&bytes);
        self.committed.blobs.insert(reference.hash.0, bytes);
        reference
    }

    /// Register exact canonical actor PVM bytes. Program identity is checked
    /// here and checked again when Refine validates its complete import set.
    pub fn import_program(&mut self, pvm: Vec<u8>) -> ProgramId {
        let program = ProgramId::of_pvm(&pvm);
        self.committed.programs.insert(program.0, pvm);
        program
    }

    /// Configure the local conformance host to accept one exact proof request.
    /// Production hosts replace this allowlist seam with their pinned proof
    /// verifier; it is intentionally excluded from persisted service state.
    pub fn allow_proof(&mut self, request: &ProofVerificationRequestV2) {
        self.proof_allowlist.insert(request.hash());
    }

    /// Authorize one exact service genesis for the next physical install.
    /// This host policy is not persisted as actor/service state.
    pub fn allow_install(&mut self, genesis: &ServiceGenesisV2) {
        self.install_allowlist.insert(install_hash(genesis));
    }

    /// Configure the conformance host to accept one exact finalized receipt.
    /// Production hosts replace this allowlist with their JAM receipt/finality
    /// verifier.
    pub fn allow_receipt(&mut self, request: &ReceiptVerificationRequestV2) {
        self.receipt_allowlist.insert(request.hash());
    }
}

impl AttestationProofHostV2 for LocalJamStoreV2 {
    fn make_proof_available(&mut self, request: &ProofVerificationRequestV2, proof: &[u8]) -> bool {
        if !request.proof_blob.matches(proof) {
            return false;
        }
        self.allow_proof(request);
        true
    }
}

impl<B> AttestationProofHostV2 for DurableJamStoreV2<B> {
    fn make_proof_available(&mut self, request: &ProofVerificationRequestV2, proof: &[u8]) -> bool {
        self.local.make_proof_available(request, proof)
    }
}

impl CommittedServiceImageHostV2 for LocalJamStoreV2 {
    fn committed_service_image(&self) -> Vec<u8> {
        self.snapshot_bytes()
    }

    fn install_committed_service_image(
        &mut self,
        image: &[u8],
    ) -> Result<(), ServiceImageInstallErrorV2> {
        self.committed = self.validate_replacement(image)?;
        Ok(())
    }
}

impl<B: CommittedImageStoreV2> CommittedServiceImageHostV2 for DurableJamStoreV2<B> {
    fn committed_service_image(&self) -> Vec<u8> {
        self.local.snapshot_bytes()
    }

    fn install_committed_service_image(
        &mut self,
        image: &[u8],
    ) -> Result<(), ServiceImageInstallErrorV2> {
        let replacement = self.local.validate_replacement(image)?;
        self.backend
            .commit(image)
            .map_err(|_| ServiceImageInstallErrorV2::PersistenceRejected)?;
        self.local.committed = replacement;
        Ok(())
    }
}

struct CommittedRows<'a>(&'a BTreeMap<Vec<u8>, Vec<u8>>);

impl StateTreeStore for CommittedRows<'_> {
    type Error = core::convert::Infallible;

    fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.0.get(key).cloned())
    }

    fn write(&mut self, _key: &[u8], _value: Option<&[u8]>) -> Result<(), Self::Error> {
        unreachable!("committed scheduler view never mutates the service tree")
    }
}

/// Private copy-on-write image for one physical IC-5 execution.
pub struct LocalJamTransactionV2 {
    staged: LocalJamStoreSnapshotV2,
    proof_allowlist: BTreeSet<super::Hash>,
    install_allowlist: BTreeSet<super::Hash>,
    receipt_allowlist: BTreeSet<super::Hash>,
}

impl LocalJamTransactionV2 {
    fn read_guest_bytes(
        kernel: &InvocationKernel,
        address: u64,
        len: u64,
        slot: u8,
    ) -> Result<Vec<u8>, ServicePvmErrorV2> {
        let address =
            u32::try_from(address).map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
        let len =
            u32::try_from(len).map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
        kernel
            .read_data_cap_window(address, len)
            .ok_or(ServicePvmErrorV2::AccumulateHostRejected(slot))
    }

    fn write_guest_bytes(
        kernel: &mut InvocationKernel,
        address: u64,
        bytes: &[u8],
        slot: u8,
    ) -> Result<(), ServicePvmErrorV2> {
        let address =
            u32::try_from(address).map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
        if bytes.is_empty() || kernel.write_data_cap_window(address, bytes) {
            Ok(())
        } else {
            Err(ServicePvmErrorV2::AccumulateHostRejected(slot))
        }
    }
}

impl AccumulateTransactionV2 for LocalJamTransactionV2 {
    fn handle(
        &mut self,
        slot: u8,
        registers: &[u64; 13],
        kernel: &mut InvocationKernel,
    ) -> Result<[u64; 2], ServicePvmErrorV2> {
        use crate::abi::{error, hostcall};

        match slot as u32 {
            hostcall::STORAGE_R => {
                let key = Self::read_guest_bytes(kernel, registers[7], registers[8], slot)?;
                let Some(value) = self.staged.rows.get(&key) else {
                    return Ok([error::HOST_NONE, 0]);
                };
                let capacity = usize::try_from(registers[10])
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let copy_len = value.len().min(capacity);
                let output = value[..copy_len].to_vec();
                Self::write_guest_bytes(kernel, registers[9], &output, slot)?;
                Ok([value.len() as u64, 0])
            }
            hostcall::STORAGE_W => {
                let key = Self::read_guest_bytes(kernel, registers[7], registers[8], slot)?;
                let value = Self::read_guest_bytes(kernel, registers[9], registers[10], slot)?;
                if value.is_empty() {
                    self.staged.rows.remove(&key);
                } else {
                    self.staged.rows.insert(key, value);
                }
                Ok([error::HOST_OK, 0])
            }
            hostcall::PREIMAGE_LOOKUP => {
                let hash: [u8; 32] = Self::read_guest_bytes(kernel, registers[7], 32, slot)?
                    .try_into()
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let Some(value) = self.staged.blobs.get(&hash) else {
                    return Ok([error::HOST_NONE, 0]);
                };
                let capacity = usize::try_from(registers[9])
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let copy_len = value.len().min(capacity);
                let output = value[..copy_len].to_vec();
                Self::write_guest_bytes(kernel, registers[8], &output, slot)?;
                Ok([value.len() as u64, 0])
            }
            hostcall::PREIMAGE_PROVIDE => {
                let hash: [u8; 32] = Self::read_guest_bytes(kernel, registers[7], 32, slot)?
                    .try_into()
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let value = Self::read_guest_bytes(kernel, registers[8], registers[9], slot)?;
                let reference = BlobRefV2::of_bytes(&value);
                if reference.hash.0 != hash {
                    return Ok([error::HOST_WHAT, 0]);
                }
                if let Some(existing) = self.staged.blobs.get(&hash)
                    && existing != &value
                {
                    return Ok([error::HOST_WHAT, 0]);
                }
                self.staged.blobs.insert(hash, value);
                Ok([error::HOST_OK, 0])
            }
            hostcall::PROOF_VERIFY => {
                let bytes = Self::read_guest_bytes(kernel, registers[7], registers[8], slot)?;
                let request = ProofVerificationRequestV2::decode(&bytes)
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let proof_available = self
                    .staged
                    .blobs
                    .get(&request.proof_blob.hash.0)
                    .is_some_and(|bytes| request.proof_blob.matches(bytes));
                Ok([
                    if proof_available && self.proof_allowlist.contains(&request.hash()) {
                        error::HOST_OK
                    } else {
                        error::HOST_NONE
                    },
                    0,
                ])
            }
            hostcall::INSTALL_AUTH_VERIFY => {
                let bytes = Self::read_guest_bytes(kernel, registers[7], registers[8], slot)?;
                let genesis = ServiceGenesisV2::decode(&bytes)
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                Ok([
                    if self.install_allowlist.contains(&install_hash(&genesis)) {
                        error::HOST_OK
                    } else {
                        error::HOST_WHAT
                    },
                    0,
                ])
            }
            hostcall::RECEIPT_VERIFY => {
                let bytes = Self::read_guest_bytes(kernel, registers[7], registers[8], slot)?;
                let request = ReceiptVerificationRequestV2::decode(&bytes)
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                Ok([
                    if self.receipt_allowlist.contains(&request.hash()) {
                        error::HOST_OK
                    } else {
                        error::HOST_NONE
                    },
                    0,
                ])
            }
            _ => Err(ServicePvmErrorV2::AccumulateHostRejected(slot)),
        }
    }
}

impl AccumulateProtocolHostV2 for LocalJamStoreV2 {
    type Transaction = LocalJamTransactionV2;

    fn begin(&mut self) -> Result<Self::Transaction, ServicePvmErrorV2> {
        Ok(LocalJamTransactionV2 {
            staged: self.committed.clone(),
            proof_allowlist: self.proof_allowlist.clone(),
            install_allowlist: self.install_allowlist.clone(),
            receipt_allowlist: self.receipt_allowlist.clone(),
        })
    }

    fn commit(&mut self, mut transaction: Self::Transaction) -> Result<(), ServicePvmErrorV2> {
        transaction.staged.commit_sequence = self
            .committed
            .commit_sequence
            .checked_add(1)
            .ok_or(ServicePvmErrorV2::AccumulateCommitRejected)?;
        self.committed = transaction.staged;
        Ok(())
    }
}

impl<B: CommittedImageStoreV2> AccumulateProtocolHostV2 for DurableJamStoreV2<B> {
    type Transaction = LocalJamTransactionV2;

    fn begin(&mut self) -> Result<Self::Transaction, ServicePvmErrorV2> {
        self.local.begin()
    }

    fn commit(&mut self, mut transaction: Self::Transaction) -> Result<(), ServicePvmErrorV2> {
        transaction.staged.commit_sequence = self
            .local
            .committed
            .commit_sequence
            .checked_add(1)
            .ok_or(ServicePvmErrorV2::AccumulateCommitRejected)?;
        let image = transaction.staged.encode();
        self.backend
            .commit(&image)
            .map_err(|_| ServicePvmErrorV2::AccumulateCommitRejected)?;
        self.local.committed = transaction.staged;
        Ok(())
    }
}

fn install_hash(genesis: &ServiceGenesisV2) -> super::Hash {
    super::Hash::digest(
        b"vos/service-install-authorization/v2",
        &[&genesis.encode()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct InjectedFailure;

    #[derive(Debug, Default)]
    struct TestImageStore {
        image: Option<Vec<u8>>,
        fail_next_commit: bool,
    }

    impl CommittedImageStoreV2 for TestImageStore {
        type Error = InjectedFailure;

        fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.image.clone())
        }

        fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error> {
            if core::mem::take(&mut self.fail_next_commit) {
                return Err(InjectedFailure);
            }
            self.image = Some(image.to_vec());
            Ok(())
        }
    }

    fn valid_header() -> StoreHeaderV2 {
        StoreHeaderV2::current(
            super::super::ServiceIdentityV2 {
                space: super::super::SpaceId([1; 32]),
                root_service: super::super::RootServiceId([2; 32]),
                deployment: super::super::DeploymentId([3; 32]),
                service_program: ProgramId([4; 32]),
                service_abi: super::super::ABI_VERSION,
                execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
            },
            super::super::ConsistencyModeV2::Local,
        )
    }

    #[test]
    fn snapshots_exclude_uncommitted_transactions() {
        let mut store = LocalJamStoreV2::new();
        let blob = store.import_blob(b"installation state".to_vec());
        let program = store.import_program(b"canonical actor pvm".to_vec());
        let before = store.snapshot();

        let mut transaction = store.begin().unwrap();
        transaction
            .staged
            .rows
            .insert(b"staged".to_vec(), b"value".to_vec());
        transaction.staged.blobs.insert(
            BlobRefV2::of_bytes(b"staged blob").hash.0,
            b"staged blob".to_vec(),
        );
        drop(transaction);

        assert_eq!(store.snapshot(), before);
        assert_eq!(store.blob(&blob), Some(b"installation state".as_slice()));
        assert_eq!(
            store.program(program),
            Some(b"canonical actor pvm".as_slice())
        );
        assert_eq!(store.row(b"staged"), None);
    }

    #[test]
    fn commit_swaps_rows_and_blobs_as_one_image() {
        let mut store = LocalJamStoreV2::new();
        let mut transaction = store.begin().unwrap();
        let bytes = b"continuation page".to_vec();
        let reference = BlobRefV2::of_bytes(&bytes);
        transaction
            .staged
            .rows
            .insert(b"header".to_vec(), b"new root".to_vec());
        transaction.staged.blobs.insert(reference.hash.0, bytes);
        store.commit(transaction).unwrap();

        assert_eq!(store.commit_sequence(), 1);
        assert_eq!(store.row(b"header"), Some(b"new root".as_slice()));
        assert_eq!(
            store.blob(&reference),
            Some(b"continuation page".as_slice())
        );

        let restarted = LocalJamStoreV2::from_snapshot(store.snapshot());
        assert_eq!(restarted, store);
    }

    #[test]
    fn committed_snapshot_wire_restores_and_rejects_identity_drift() {
        let mut store = LocalJamStoreV2::new();
        let blob = store.import_blob(b"continuation page".to_vec());
        let program = store.import_program(b"canonical actor pvm".to_vec());
        let header = valid_header();
        let mut transaction = store.begin().unwrap();
        transaction
            .staged
            .rows
            .insert(super::super::header_storage_key().to_vec(), header.encode());
        store.commit(transaction).unwrap();

        let bytes = store.snapshot_bytes();
        let restarted = LocalJamStoreV2::from_snapshot_bytes(&bytes).unwrap();
        assert_eq!(restarted, store);
        assert_eq!(restarted.blob(&blob), Some(b"continuation page".as_slice()));
        assert_eq!(
            restarted.program(program),
            Some(b"canonical actor pvm".as_slice())
        );

        let mut corrupt_blob = store.snapshot();
        corrupt_blob
            .blobs
            .insert(blob.hash.0, b"different bytes".to_vec());
        assert_eq!(
            LocalJamStoreSnapshotV2::decode(&corrupt_blob.encode()),
            Err(DecodeError::NonCanonical)
        );

        let mut corrupt_program = store.snapshot();
        corrupt_program
            .programs
            .insert(program.0, b"different pvm".to_vec());
        assert_eq!(
            LocalJamStoreSnapshotV2::decode(&corrupt_program.encode()),
            Err(DecodeError::NonCanonical)
        );
    }

    #[test]
    fn service_image_install_validates_identity_and_persists_before_visibility() {
        let mut source = LocalJamStoreV2::new();
        let mut source_transaction = source.begin().unwrap();
        source_transaction.staged.rows.insert(
            super::super::header_storage_key().to_vec(),
            valid_header().encode(),
        );
        source.commit(source_transaction).unwrap();
        let image = source.snapshot_bytes();

        let mut fresh = LocalJamStoreV2::new();
        fresh.install_committed_service_image(&image).unwrap();
        assert!(fresh.snapshot().same_service_state(&source.snapshot()));

        let mut different_header = valid_header();
        different_header.service.root_service = super::super::RootServiceId([99; 32]);
        let mut different = LocalJamStoreV2::new();
        let mut transaction = different.begin().unwrap();
        transaction.staged.rows.insert(
            super::super::header_storage_key().to_vec(),
            different_header.encode(),
        );
        different.commit(transaction).unwrap();
        let before = different.snapshot();
        assert_eq!(
            different.install_committed_service_image(&image),
            Err(ServiceImageInstallErrorV2::ServiceMismatch)
        );
        assert_eq!(different.snapshot(), before);

        let backend = TestImageStore {
            fail_next_commit: true,
            ..TestImageStore::default()
        };
        let mut durable = DurableJamStoreV2::open(backend).unwrap();
        let before = durable.snapshot();
        assert_eq!(
            durable.install_committed_service_image(&image),
            Err(ServiceImageInstallErrorV2::PersistenceRejected)
        );
        assert_eq!(durable.snapshot(), before);
        assert!(durable.backend().image.is_none());
    }

    #[test]
    fn durable_boundary_never_exposes_a_failed_commit_and_retry_is_exact() {
        let backend = TestImageStore {
            fail_next_commit: true,
            ..TestImageStore::default()
        };
        let mut store = DurableJamStoreV2::open(backend).unwrap();
        let blob = store.import_blob(b"continuation page".to_vec());
        let program = store.import_program(b"canonical actor pvm".to_vec());
        let before = store.snapshot();

        let mut rejected = store.begin().unwrap();
        rejected.staged.rows.insert(
            super::super::header_storage_key().to_vec(),
            valid_header().encode(),
        );
        assert_eq!(
            store.commit(rejected),
            Err(ServicePvmErrorV2::AccumulateCommitRejected)
        );
        assert_eq!(store.snapshot(), before);
        assert!(store.backend().image.is_none());

        let mut retry = store.begin().unwrap();
        retry.staged.rows.insert(
            super::super::header_storage_key().to_vec(),
            valid_header().encode(),
        );
        store.commit(retry).unwrap();
        assert_eq!(store.commit_sequence(), 1);

        let expected = store.snapshot();
        let (_, backend) = store.into_parts();
        let restarted = DurableJamStoreV2::open(backend).unwrap();
        assert_eq!(restarted.snapshot(), expected);
        assert_eq!(restarted.blob(&blob), Some(b"continuation page".as_slice()));
        assert_eq!(
            restarted.program(program),
            Some(b"canonical actor pvm".as_slice())
        );
    }

    #[test]
    fn file_backend_atomically_reopens_the_committed_image() {
        let directory = std::env::temp_dir().join(alloc::format!(
            "vos-v2-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let path = directory.join("service.v2");
        let mut store = DurableJamStoreV2::open(FileCommittedImageStoreV2::new(&path)).unwrap();
        let mut transaction = store.begin().unwrap();
        transaction.staged.rows.insert(
            super::super::header_storage_key().to_vec(),
            valid_header().encode(),
        );
        store.commit(transaction).unwrap();
        let expected = store.snapshot();
        drop(store);

        let restarted = DurableJamStoreV2::open(FileCommittedImageStoreV2::new(&path)).unwrap();
        assert_eq!(restarted.snapshot(), expected);
        assert!(!path.with_file_name("service.v2.v2-next").exists());

        std::fs::remove_dir_all(directory).unwrap();
    }
}
