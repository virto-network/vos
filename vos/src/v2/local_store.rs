//! Atomic local JAM storage host for the v2 conformance runtime.
//!
//! This module implements only the physical storage and preimage protocol
//! calls used by the canonical service PVM. It deliberately does not decode or
//! apply [`super::TransitionV2`]: all validation and mutation semantics remain
//! guest-owned at the IC-5 Accumulate entry.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use javm::kernel::InvocationKernel;

use super::{
    AccumulateProtocolHostV2, AccumulateTransactionV2, BlobRefV2, ProgramId,
    ProofVerificationRequestV2, ServicePvmErrorV2, ServiceStateTreeV2, StateKeyV2, StateTreeStore,
    StoreHeaderV2, StoreOpenError, V2Wire,
};

/// Recoverable committed image of a local v2 service account.
///
/// Rows include the guest-owned header, authenticated state nodes, receipts,
/// deduplication records, and CRDT DAG nodes. Blobs contain exact bytes keyed
/// by the canonical VOS blob hash. A host may persist this value using its own
/// crash-safe encoding; it contains no in-flight transaction state.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalStoreReadErrorV2 {
    InvalidHeader(StoreOpenError),
    CorruptStateTree,
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
        }
    }

    /// Restore exactly one previously committed service-account image.
    pub fn from_snapshot(snapshot: LocalJamStoreSnapshotV2) -> Self {
        Self {
            committed: snapshot,
            proof_allowlist: BTreeSet::new(),
        }
    }

    /// Capture only committed state. An active Accumulate transaction is owned
    /// by the service invocation and cannot be observed through this object.
    pub fn snapshot(&self) -> LocalJamStoreSnapshotV2 {
        self.committed.clone()
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
