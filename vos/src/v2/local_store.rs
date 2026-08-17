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
use std::sync::Arc;

use javm::kernel::InvocationKernel;

use crate::attestation::AttestationProofHostV2;

use super::wire::{DecodeError, Decoder, Encoder};
use super::{
    AccumulateProtocolHostV2, AccumulateTransactionV2, AccumulatedTimeoutV2, AccumulationReceiptV2,
    ActorId, ActorUpgradeV2, AttestationDeliveryV2, BlobRefV2, DedupRecordV2, DeliveryRecordV2,
    DirectIngressV2, IngressRecordV2, MessageRecordV2, ProgramId, ProofVerificationRequestV2,
    PublicationRecordV2, ReceiptVerificationRequestV2, ReplyAdmissionRecordV2,
    RoleCredentialVerificationRequestV2, ServiceGenesisV2, ServicePvmErrorV2, ServiceStateTreeV2,
    StateKeyV2, StateTreeStore, StoreHeaderV2, StoreOpenError, V2Wire,
};

fn proof_verification_for_attestation(
    attestation: &AttestationDeliveryV2,
) -> ProofVerificationRequestV2 {
    ProofVerificationRequestV2 {
        actor_program: attestation.statement.actor_program,
        execution_semantics: attestation
            .statement
            .accumulation_receipt
            .service
            .execution_semantics,
        statement: attestation.proof.statement,
        trace: attestation.proof.trace,
        proof_blob: attestation.proof.proof_blob.clone(),
    }
}

/// Cloneable in-memory image of a committed local v2 service account.
///
/// Rows include the guest-owned header, authenticated state nodes, receipts,
/// deduplication records, and CRDT DAG nodes. Blobs and programs contain exact
/// bytes keyed by their canonical identities. Its strict v2 wire is the
/// crash-recovery image persisted by a host. It contains no in-flight
/// transaction or process-local verifier policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalJamStoreSnapshotV2 {
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    blobs: BTreeMap<[u8; 32], Vec<u8>>,
    programs: BTreeMap<[u8; 32], Vec<u8>>,
    commit_sequence: u64,
    /// Production-host seal showing that this exact durable image
    /// was committed while the production proof verifier was installed.
    /// It is not actor state and is ignored by `same_service_state`.
    proof_verifier_provenance: Option<super::Hash>,
}

impl LocalJamStoreSnapshotV2 {
    fn encode_provenance_input(&self, out: &mut Vec<u8>) {
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

    fn expected_proof_verifier_provenance(&self) -> super::Hash {
        let mut input = Vec::new();
        self.encode_provenance_input(&mut input);
        super::Hash::digest(b"vos/proof-verifier-provenance/v2", &[&input])
    }

    fn seal_proof_verifier_provenance(&mut self) {
        self.proof_verifier_provenance = Some(self.expected_proof_verifier_provenance());
    }

    pub(crate) const fn has_proof_verifier_provenance(&self) -> bool {
        self.proof_verifier_provenance.is_some()
    }

    /// Compare consensus-visible rows, blobs, and programs while ignoring
    /// host-local commit metadata.
    pub fn same_service_state(&self, other: &Self) -> bool {
        self.rows == other.rows && self.blobs == other.blobs && self.programs == other.programs
    }

    /// Service identity declared by this image, when genesis has committed.
    /// Snapshot recovery uses this read-only view before mutating either the
    /// proof side-CAS or the locally visible service image.
    pub(crate) fn service_identity(&self) -> Result<Option<super::ServiceIdentityV2>, DecodeError> {
        self.rows
            .get(super::header_storage_key())
            .map(|bytes| {
                StoreHeaderV2::open(bytes)
                    .map(|header| header.service)
                    .map_err(|_| DecodeError::NonCanonical)
            })
            .transpose()
    }

    /// Proof blobs required to finish pending transport work.
    ///
    /// Permanent reply-admission rows are replay markers, not pending work:
    /// duplicate routing returns from the admission before reading proof
    /// bytes. Retaining their proofs here would make every Raft snapshot grow
    /// with the complete attested-reply history.
    pub(crate) fn referenced_proof_verifications(
        &self,
    ) -> Result<Vec<ProofVerificationRequestV2>, DecodeError> {
        let mut requests = Vec::new();
        let publication_prefix = super::storage::publication_storage_prefix();
        for (key, bytes) in self
            .rows
            .range(publication_prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(publication_prefix))
        {
            let publication = PublicationRecordV2::decode(bytes)?;
            if super::publication_storage_key(publication.input).as_slice() != key.as_slice() {
                return Err(DecodeError::NonCanonical);
            }
            if publication.published.proof.is_some() {
                let attestation = publication
                    .published
                    .attestation
                    .as_deref()
                    .ok_or(DecodeError::NonCanonical)?;
                requests.push(proof_verification_for_attestation(attestation));
            }
        }

        requests.sort_unstable_by_key(ProofVerificationRequestV2::hash);
        requests.dedup();
        Ok(requests)
    }

    /// Proof decisions whose validity still affects durable local behavior.
    /// Pending publications need their artifact for routing; permanent reply
    /// admissions prove that an external attestation was allowed to resume an
    /// actor. A production verifier installed after opening a conformance
    /// store must revalidate both classes before the root becomes routable.
    pub(crate) fn proof_verification_history(
        &self,
    ) -> Result<Vec<ProofVerificationRequestV2>, DecodeError> {
        let mut requests = self.referenced_proof_verifications()?;
        let admission_prefix = super::storage::reply_admission_storage_prefix();
        for (key, bytes) in self
            .rows
            .range(admission_prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(admission_prefix))
        {
            let admission = ReplyAdmissionRecordV2::decode(bytes)?;
            if super::reply_admission_storage_key(admission.call_id).as_slice() != key.as_slice() {
                return Err(DecodeError::NonCanonical);
            }
            if let Some(attestation) = admission.awaited_reply.attestation.as_deref() {
                requests.push(proof_verification_for_attestation(attestation));
            }
        }
        requests.sort_unstable_by_key(ProofVerificationRequestV2::hash);
        requests.dedup();
        Ok(requests)
    }
}

impl V2Wire for LocalJamStoreSnapshotV2 {
    const MAGIC: [u8; 4] = *b"VSS3";

    fn encode_body(&self, out: &mut Vec<u8>) {
        self.encode_provenance_input(out);
        Encoder(out).option(&self.proof_verifier_provenance, |encoder, provenance| {
            encoder.fixed(&provenance.0);
        });
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let commit_sequence = decoder.u64()?;
        let rows = decode_byte_map(decoder)?;
        let blobs = decode_content_map(decoder, |key, bytes| {
            BlobRefV2::of_bytes(bytes).hash.0 == *key
        })?;
        let programs =
            decode_content_map(decoder, |key, bytes| ProgramId::of_pvm(bytes).0 == *key)?;
        let proof_verifier_provenance =
            decoder.option(|decoder| Ok(super::Hash(decoder.fixed()?)))?;
        if rows.is_empty() != (commit_sequence == 0) {
            return Err(DecodeError::NonCanonical);
        }
        if !rows.is_empty() {
            let header = rows
                .get(super::header_storage_key())
                .ok_or(DecodeError::NonCanonical)?;
            StoreHeaderV2::open(header).map_err(|_| DecodeError::NonCanonical)?;
        }
        let snapshot = Self {
            rows,
            blobs,
            programs,
            commit_sequence,
            proof_verifier_provenance,
        };
        if snapshot
            .proof_verifier_provenance
            .is_some_and(|provenance| provenance != snapshot.expected_proof_verifier_provenance())
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(snapshot)
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
/// `commit` must return success only after the image is recoverable following
/// a process restart. A filesystem implementation can use atomic rename; a
/// Raft implementation can wait for quorum availability. The service host
/// never exposes the candidate image before this boundary succeeds.
pub trait CommittedImageStoreV2 {
    type Error;

    fn load(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;

    fn commit(&mut self, image: &[u8]) -> Result<(), Self::Error>;
}

/// Durable side-CAS for proof artifacts referenced by committed publications.
///
/// Proof bytes remain outside the consensus service image, but a successful
/// proved Apply must not outlive the only copy needed to route its reply after
/// restart. Implementations persist bytes by their authenticated [`BlobRefV2`]
/// before guest Accumulate can publish the corresponding commitment.
pub trait ProofArtifactStoreV2 {
    type Error;

    fn load_proof(&self, reference: &BlobRefV2) -> Result<Option<Vec<u8>>, Self::Error>;

    fn commit_proof(&mut self, reference: &BlobRefV2, proof: &[u8]) -> Result<(), Self::Error>;

    /// Load producer-private invocation arguments by their durable invocation
    /// identity and committed content address.
    fn load_private_ingress(
        &self,
        _invocation: super::InvocationId,
        _reference: &BlobRefV2,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }

    /// Persist producer-private invocation arguments before guest admission.
    /// A successful implementation must also durably retain enough ownership
    /// metadata for restart reconciliation to preserve the artifact until a
    /// later guest ingress takes ownership or the host explicitly retires it.
    /// `false` means this backend does not provide the required sidecar.
    fn commit_private_ingress(
        &mut self,
        _invocation: super::InvocationId,
        _reference: &BlobRefV2,
        _arguments: &[u8],
        _staging: PrivateIngressStagingV2,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Delete arguments after their terminal Local slice has committed.
    fn delete_private_ingress(
        &mut self,
        _invocation: super::InvocationId,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Reconcile producer-private ingress artifacts with guest-admitted
    /// requests that still need their plaintext. Implementors must preserve
    /// guest-owned live artifacts plus replicated pre-admission artifacts
    /// durably acknowledged by [`Self::commit_private_ingress`]. Local
    /// pre-admission orphans, guest-consumed artifacts, and incomplete
    /// temporary files must be removed. Both slices are strictly ordered by
    /// invocation identity without duplicates and are mutually disjoint.
    fn reconcile_private_ingresses(
        &mut self,
        retained: &[(super::InvocationId, BlobRefV2)],
        terminal: &[super::InvocationId],
    ) -> Result<(), Self::Error>;

    /// Load one producer-private Task record. The default keeps compatibility
    /// with proof-only test backends while reporting that no record exists.
    fn load_producer_record(
        &self,
        _actor: ActorId,
        _tag: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }

    /// Atomically persist a producer-private Task record. `false` means this
    /// backend has no durable record sidecar and production Refine must fail
    /// before proposing its transition.
    fn commit_producer_record(
        &mut self,
        _actor: ActorId,
        _tag: &[u8; 32],
        _record: &[u8],
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Delete one producer-private record after the operator has proved or
    /// retired it. `false` means either absent or unsupported.
    fn delete_producer_record(
        &mut self,
        _actor: ActorId,
        _tag: &[u8; 32],
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

/// Host-private ownership state for a private input persisted before guest
/// admission. Local staging has no external acknowledgement and is discarded
/// if no guest ingress owns it after restart. Replicated staging survives
/// restart until the matching ordered admission is applied or explicitly
/// aborted by the replication protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateIngressStagingV2 {
    Local,
    Replicated,
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
    CorruptStore(LocalStoreReadErrorV2),
}

impl<E: core::fmt::Debug> core::fmt::Display for DurableStoreOpenErrorV2<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "cannot open durable VOS v2 service state: {self:?}")
    }
}

impl<E: core::fmt::Debug> core::error::Error for DurableStoreOpenErrorV2<E> {}

/// Atomic filesystem sink for canonical service-account images.
///
/// The candidate is flushed to a sibling temporary file, renamed over the
/// committed path, then followed by a parent-directory sync. One path is
/// owned by one service writer; replicated services use a quorum backend.
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

    fn proof_directory(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".proofs");
        self.path.with_file_name(name)
    }

    fn proof_path(&self, reference: &BlobRefV2) -> PathBuf {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = [0_u8; 64];
        for (index, byte) in reference.hash.0.iter().copied().enumerate() {
            name[index * 2] = HEX[usize::from(byte >> 4)];
            name[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        self.proof_directory()
            .join(std::str::from_utf8(&name).expect("lowercase hexadecimal is valid UTF-8"))
    }

    fn producer_record_directory(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".records");
        self.path.with_file_name(name)
    }

    fn private_ingress_directory(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".private-inputs");
        self.path.with_file_name(name)
    }

    fn legacy_private_ingress_path(&self, invocation: super::InvocationId) -> PathBuf {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = [0_u8; 64];
        for (index, byte) in invocation.0.iter().copied().enumerate() {
            name[index * 2] = HEX[usize::from(byte >> 4)];
            name[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        self.private_ingress_directory()
            .join(std::str::from_utf8(&name).expect("lowercase hexadecimal is valid UTF-8"))
    }

    fn private_ingress_path(&self, invocation: super::InvocationId) -> PathBuf {
        self.legacy_private_ingress_path(invocation)
            .with_extension("vpi3")
    }

    fn write_private_ingress_artifact(
        &self,
        invocation: super::InvocationId,
        staging: PrivateIngressStagingV2,
        reference: &BlobRefV2,
        arguments: &[u8],
    ) -> std::io::Result<()> {
        use std::io::Write;

        let directory = self.private_ingress_directory();
        std::fs::create_dir_all(&directory)?;
        if let Some(parent) = directory.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        let path = self.private_ingress_path(invocation);
        let temporary = path.with_extension("v2-next");
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&encode_private_ingress_artifact(
            staging, reference, arguments,
        ))?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &path)?;
        std::fs::File::open(&directory)?.sync_all()?;
        Ok(())
    }

    fn producer_record_path(&self, actor: ActorId, tag: &[u8; 32]) -> PathBuf {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = [0_u8; 128];
        for (index, byte) in actor.0.iter().chain(tag).copied().enumerate() {
            name[index * 2] = HEX[usize::from(byte >> 4)];
            name[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
        }
        self.producer_record_directory()
            .join(std::str::from_utf8(&name).expect("lowercase hexadecimal is valid UTF-8"))
    }
}

fn decode_private_ingress_file_name(name: &str) -> Option<(super::InvocationId, bool)> {
    let (name, current) = match name.strip_suffix(".vpi3") {
        Some(name) => (name, true),
        None => (name, false),
    };
    if name.len() != 64 {
        return None;
    }
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
    let mut invocation = [0_u8; 32];
    for (index, pair) in name.as_bytes().chunks_exact(2).enumerate() {
        invocation[index] = nibble(pair[0])?.checked_shl(4)? | nibble(pair[1])?;
    }
    Some((super::InvocationId(invocation), current))
}

const PRIVATE_INGRESS_ARTIFACT_MAGIC: &[u8; 4] = b"VPI3";
const LEGACY_PRIVATE_INGRESS_ARTIFACT_MAGIC: &[u8; 4] = b"VPI2";

fn encode_private_ingress_artifact(
    staging: PrivateIngressStagingV2,
    reference: &BlobRefV2,
    bytes: &[u8],
) -> Vec<u8> {
    let mut artifact = Vec::with_capacity(5 + 32 + 8 + bytes.len());
    artifact.extend_from_slice(PRIVATE_INGRESS_ARTIFACT_MAGIC);
    artifact.push(match staging {
        PrivateIngressStagingV2::Local => 0,
        PrivateIngressStagingV2::Replicated => 1,
    });
    artifact.extend_from_slice(&reference.hash.0);
    artifact.extend_from_slice(&reference.len.to_le_bytes());
    artifact.extend_from_slice(bytes);
    artifact
}

fn decode_private_ingress_artifact(
    bytes: &[u8],
) -> Option<(PrivateIngressStagingV2, BlobRefV2, &[u8])> {
    if bytes.get(..4)? != PRIVATE_INGRESS_ARTIFACT_MAGIC {
        return None;
    }
    let staging = match *bytes.get(4)? {
        0 => PrivateIngressStagingV2::Local,
        1 => PrivateIngressStagingV2::Replicated,
        _ => return None,
    };
    let hash = super::Hash(bytes.get(5..37)?.try_into().ok()?);
    let len = u64::from_le_bytes(bytes.get(37..45)?.try_into().ok()?);
    let payload = bytes.get(45..)?;
    let reference = BlobRefV2 { hash, len };
    (!payload.is_empty()
        && payload.len() <= super::ACTOR_PRIVATE_INPUT_MAX_BYTES
        && reference.matches(payload))
    .then_some((staging, reference, payload))
}

fn decode_legacy_private_ingress_artifact(bytes: &[u8]) -> Option<(BlobRefV2, &[u8])> {
    if bytes.get(..4)? != LEGACY_PRIVATE_INGRESS_ARTIFACT_MAGIC {
        return None;
    }
    let hash = super::Hash(bytes.get(4..36)?.try_into().ok()?);
    let len = u64::from_le_bytes(bytes.get(36..44)?.try_into().ok()?);
    let payload = bytes.get(44..)?;
    let reference = BlobRefV2 { hash, len };
    (!payload.is_empty()
        && payload.len() <= super::ACTOR_PRIVATE_INPUT_MAX_BYTES
        && reference.matches(payload))
    .then_some((reference, payload))
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

impl ProofArtifactStoreV2 for FileCommittedImageStoreV2 {
    type Error = std::io::Error;

    fn load_proof(&self, reference: &BlobRefV2) -> Result<Option<Vec<u8>>, Self::Error> {
        match std::fs::read(self.proof_path(reference)) {
            Ok(bytes) if reference.matches(&bytes) => Ok(Some(bytes)),
            Ok(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "proof artifact does not match its content address",
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn commit_proof(&mut self, reference: &BlobRefV2, proof: &[u8]) -> Result<(), Self::Error> {
        use std::io::Write;

        if !reference.matches(proof) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "proof artifact does not match its content address",
            ));
        }
        let directory = self.proof_directory();
        std::fs::create_dir_all(&directory)?;
        if let Some(parent) = directory.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        let path = self.proof_path(reference);
        match std::fs::read(&path) {
            Ok(existing) if existing == proof => return Ok(()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "proof content address already contains different bytes",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        let temporary = path.with_extension("v2-next");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(proof)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &path)?;
        std::fs::File::open(&directory)?.sync_all()?;
        Ok(())
    }

    fn load_private_ingress(
        &self,
        invocation: super::InvocationId,
        reference: &BlobRefV2,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        match std::fs::read(self.private_ingress_path(invocation)) {
            Ok(artifact) => {
                let Some((_, stored_reference, bytes)) = decode_private_ingress_artifact(&artifact)
                else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "private ingress artifact is not canonical",
                    ));
                };
                if stored_reference != *reference {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "private ingress does not match its committed content address",
                    ));
                }
                Ok(Some(bytes.to_vec()))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn commit_private_ingress(
        &mut self,
        invocation: super::InvocationId,
        reference: &BlobRefV2,
        arguments: &[u8],
        staging: PrivateIngressStagingV2,
    ) -> Result<bool, Self::Error> {
        if !reference.matches(arguments) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "private ingress does not match its committed content address",
            ));
        }
        let path = self.private_ingress_path(invocation);
        match std::fs::read(&path) {
            Ok(existing) => {
                let Some((stored_staging, stored_reference, bytes)) =
                    decode_private_ingress_artifact(&existing)
                else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "private ingress artifact is not canonical",
                    ));
                };
                if stored_reference != *reference || bytes != arguments {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "private ingress invocation already contains different bytes",
                    ));
                }
                if stored_staging == staging
                    || stored_staging == PrivateIngressStagingV2::Replicated
                {
                    return Ok(true);
                }
                // A replicated acknowledgement is stronger than an earlier
                // Local staging write. Promote atomically; never downgrade a
                // replicated artifact merely because local admission races it.
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        self.write_private_ingress_artifact(invocation, staging, reference, arguments)?;
        Ok(true)
    }

    fn delete_private_ingress(
        &mut self,
        invocation: super::InvocationId,
    ) -> Result<bool, Self::Error> {
        let directory = self.private_ingress_directory();
        match std::fs::remove_file(self.private_ingress_path(invocation)) {
            Ok(()) => {
                std::fs::File::open(directory)?.sync_all()?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn reconcile_private_ingresses(
        &mut self,
        retained: &[(super::InvocationId, BlobRefV2)],
        terminal: &[super::InvocationId],
    ) -> Result<(), Self::Error> {
        let directory = self.private_ingress_directory();
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if retained.is_empty() {
                    return Ok(());
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "private ingress sidecar is missing",
                ));
            }
            Err(error) => return Err(error),
        };

        let mut present = BTreeSet::new();
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let decoded_name = decode_private_ingress_file_name(&name);
            let Some((invocation, current)) = decoded_name else {
                if entry.file_type()?.is_dir() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "private ingress sidecar contains an unexpected directory",
                    ));
                }
                std::fs::remove_file(path)?;
                continue;
            };
            if terminal.binary_search(&invocation).is_ok() {
                std::fs::remove_file(path)?;
                continue;
            }
            let artifact = std::fs::read(&path)?;
            if let Ok(index) =
                retained.binary_search_by_key(&invocation, |(candidate, _)| *candidate)
            {
                let expected = &retained[index].1;
                let decoded = if current {
                    decode_private_ingress_artifact(&artifact)
                        .map(|(_, reference, bytes)| (reference, bytes))
                } else {
                    (artifact.len() <= super::ACTOR_PRIVATE_INPUT_MAX_BYTES
                        && expected.matches(&artifact))
                    .then_some((expected.clone(), artifact.as_slice()))
                    .or_else(|| decode_legacy_private_ingress_artifact(&artifact))
                };
                let Some((stored_reference, bytes)) = decoded else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "private ingress artifact is not canonical",
                    ));
                };
                if *expected != stored_reference {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "private ingress does not match its guest-owned content address",
                    ));
                }
                if !current {
                    let current_path = self.private_ingress_path(invocation);
                    match std::fs::read(&current_path) {
                        Ok(existing)
                            if decode_private_ingress_artifact(&existing).is_some_and(
                                |(_, reference, current_bytes)| {
                                    reference == *expected && current_bytes == bytes
                                },
                            ) => {}
                        Ok(_) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "legacy and current private ingress artifacts disagree",
                            ));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            self.write_private_ingress_artifact(
                                invocation,
                                PrivateIngressStagingV2::Local,
                                expected,
                                bytes,
                            )?;
                        }
                        Err(error) => return Err(error),
                    }
                    std::fs::remove_file(path)?;
                } else if !decode_private_ingress_artifact(&artifact).is_some_and(
                    |(staging, reference, _)| {
                        staging == PrivateIngressStagingV2::Local && reference == *expected
                    },
                ) {
                    self.write_private_ingress_artifact(
                        invocation,
                        PrivateIngressStagingV2::Local,
                        expected,
                        bytes,
                    )?;
                }
                present.insert(invocation);
                continue;
            }
            if !current {
                // Batch 60 stored raw Local bytes at the unversioned path;
                // the short-lived VPI2 review format used the same name.
                // Neither has independently authenticated replicated
                // ownership, so an orphan is always retired.
                std::fs::remove_file(path)?;
                continue;
            }
            match decode_private_ingress_artifact(&artifact) {
                Some((PrivateIngressStagingV2::Replicated, _, _)) => {}
                Some((PrivateIngressStagingV2::Local, _, _)) => std::fs::remove_file(path)?,
                None => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "private ingress artifact is not canonical",
                    ));
                }
            }
        }
        if retained
            .iter()
            .any(|(invocation, _)| !present.contains(invocation))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "private ingress sidecar is missing",
            ));
        }
        std::fs::File::open(directory)?.sync_all()?;
        Ok(())
    }

    fn load_producer_record(
        &self,
        actor: ActorId,
        tag: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        match std::fs::read(self.producer_record_path(actor, tag)) {
            Ok(bytes)
                if crate::provable::ProofRecordEntry::decode(&bytes)
                    .is_some_and(|entry| entry.encode() == bytes) =>
            {
                Ok(Some(bytes))
            }
            Ok(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "producer record is not canonical",
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn commit_producer_record(
        &mut self,
        actor: ActorId,
        tag: &[u8; 32],
        record: &[u8],
    ) -> Result<bool, Self::Error> {
        use std::io::Write;

        if !crate::provable::ProofRecordEntry::decode(record)
            .is_some_and(|entry| entry.encode() == record)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "producer record is not canonical",
            ));
        }
        let directory = self.producer_record_directory();
        std::fs::create_dir_all(&directory)?;
        if let Some(parent) = directory.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        let path = self.producer_record_path(actor, tag);
        match std::fs::read(&path) {
            Ok(existing) if existing == record => return Ok(true),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "producer record tag already contains different bytes",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let temporary = path.with_extension("v2-next");
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(record)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &path)?;
        std::fs::File::open(&directory)?.sync_all()?;
        Ok(true)
    }

    fn delete_producer_record(
        &mut self,
        actor: ActorId,
        tag: &[u8; 32],
    ) -> Result<bool, Self::Error> {
        let directory = self.producer_record_directory();
        let path = self.producer_record_path(actor, tag);
        match std::fs::remove_file(path) {
            Ok(()) => {
                std::fs::File::open(directory)?.sync_all()?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalStoreReadErrorV2 {
    InvalidHeader(StoreOpenError),
    CorruptStateTree,
    CorruptReceipt,
    CorruptPublication,
    CorruptDelivery,
    CorruptIngress,
    CorruptReplyRoute,
    CorruptExpiration,
    CorruptPendingDeadline,
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
#[derive(Clone, Default)]
pub struct LocalJamStoreV2 {
    committed: LocalJamStoreSnapshotV2,
    /// Proof artifacts are verifier/CAS inputs, not consensus service state.
    /// They are deliberately excluded from snapshots and equality.
    proof_blobs: BTreeMap<[u8; 32], Vec<u8>>,
    /// Private authorization witnesses are Refine/prover inputs only. They
    /// never enter the recoverable service image or replica sync payloads.
    private_witnesses: BTreeMap<[u8; 32], Vec<u8>>,
    /// Installed proof verifier for node/production execution. `None` is
    /// retained only for the explicit conformance harness, whose tests seed
    /// exact request hashes through the legacy local allowlist seam.
    proof_verifier: Option<Arc<ProofVerifierFnV2>>,
    proof_allowlist: BTreeSet<super::Hash>,
    role_credential_allowlist: BTreeSet<super::Hash>,
    upgrade_allowlist: BTreeSet<super::Hash>,
    receipt_allowlist: BTreeSet<super::Hash>,
    install_allowlist: BTreeSet<super::Hash>,
}

pub(crate) type ProofVerifierFnV2 =
    dyn Fn(&ProofVerificationRequestV2, &[u8]) -> bool + Send + Sync + 'static;

impl core::fmt::Debug for LocalJamStoreV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalJamStoreV2")
            .field("committed", &self.committed)
            .field("proof_blobs", &self.proof_blobs.len())
            .field("private_witnesses", &self.private_witnesses.len())
            .field("proof_verifier_installed", &self.proof_verifier.is_some())
            .finish_non_exhaustive()
    }
}

/// JAM storage host whose committed image is durable before IC-5 returns.
///
/// Private-witness inputs and credential, receipt, and install verifier
/// configuration remain process-local. Proof bytes and producer-private Task
/// records use the backend's separate [`ProofArtifactStoreV2`] side stores and
/// never enter the consensus service image.
pub struct DurableJamStoreV2<B> {
    local: LocalJamStoreV2,
    backend: B,
    private_ingress_retirement_debt: BTreeSet<super::InvocationId>,
}

/// Access to the committed local conformance image carried by an Accumulate
/// host.
///
/// Both the in-memory and durable hosts expose the same read-only scheduling
/// view and process-local receipt policy. Transport remains orchestration
/// only: every service-state mutation still crosses physical IC-5 and the
/// host's [`AccumulateProtocolHostV2::commit`] boundary.
pub trait LocalJamStoreHostV2 {
    fn local_store(&self) -> &LocalJamStoreV2;

    fn local_store_mut(&mut self) -> &mut LocalJamStoreV2;
}

impl LocalJamStoreHostV2 for LocalJamStoreV2 {
    fn local_store(&self) -> &LocalJamStoreV2 {
        self
    }

    fn local_store_mut(&mut self) -> &mut LocalJamStoreV2 {
        self
    }
}

impl<B> LocalJamStoreHostV2 for DurableJamStoreV2<B> {
    fn local_store(&self) -> &LocalJamStoreV2 {
        &self.local
    }

    fn local_store_mut(&mut self) -> &mut LocalJamStoreV2 {
        &mut self.local
    }
}

impl<B> DurableJamStoreV2<B>
where
    B: CommittedImageStoreV2 + ProofArtifactStoreV2<Error = <B as CommittedImageStoreV2>::Error>,
{
    pub fn open(
        mut backend: B,
    ) -> Result<Self, DurableStoreOpenErrorV2<<B as CommittedImageStoreV2>::Error>> {
        let local = match backend.load().map_err(DurableStoreOpenErrorV2::Backend)? {
            Some(bytes) => LocalJamStoreV2::from_snapshot_bytes(&bytes)
                .map_err(DurableStoreOpenErrorV2::InvalidSnapshot)?,
            None => LocalJamStoreV2::new(),
        };
        let (retained, terminal) = local
            .private_ingress_recovery()
            .map_err(DurableStoreOpenErrorV2::CorruptStore)?;
        backend
            .reconcile_private_ingresses(&retained, &terminal)
            .map_err(DurableStoreOpenErrorV2::Backend)?;
        Ok(Self {
            local,
            backend,
            private_ingress_retirement_debt: BTreeSet::new(),
        })
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

    /// Producer-private inputs whose guest transition committed but whose
    /// host-side retirement has not yet succeeded. This is health/cleanup
    /// state, never the disposition of the committed invocation.
    pub fn private_ingress_retirement_debt(&self) -> Vec<super::InvocationId> {
        self.private_ingress_retirement_debt
            .iter()
            .copied()
            .collect()
    }
}

impl<B> DurableJamStoreV2<B>
where
    B: CommittedImageStoreV2 + ProofArtifactStoreV2<Error = <B as CommittedImageStoreV2>::Error>,
{
    pub(crate) fn persist_private_ingress(
        &mut self,
        invocation: super::InvocationId,
        arguments: &[u8],
    ) -> Result<BlobRefV2, ()> {
        self.persist_private_ingress_with_staging(
            invocation,
            arguments,
            PrivateIngressStagingV2::Local,
        )
    }

    pub(crate) fn persist_replicated_private_ingress(
        &mut self,
        invocation: super::InvocationId,
        arguments: &[u8],
    ) -> Result<BlobRefV2, ()> {
        self.persist_private_ingress_with_staging(
            invocation,
            arguments,
            PrivateIngressStagingV2::Replicated,
        )
    }

    fn persist_private_ingress_with_staging(
        &mut self,
        invocation: super::InvocationId,
        arguments: &[u8],
        staging: PrivateIngressStagingV2,
    ) -> Result<BlobRefV2, ()> {
        let reference = BlobRefV2::of_bytes(arguments);
        if arguments.is_empty() {
            return Err(());
        }
        match self
            .backend
            .load_private_ingress(invocation, &reference)
            .map_err(|_| ())?
        {
            Some(existing) if existing == arguments => {}
            Some(_) => return Err(()),
            None => {}
        }
        if !self
            .backend
            .commit_private_ingress(invocation, &reference, arguments, staging)
            .map_err(|_| ())?
        {
            return Err(());
        }
        Ok(reference)
    }

    pub(crate) fn private_ingress(
        &self,
        invocation: super::InvocationId,
        reference: &BlobRefV2,
    ) -> Option<Vec<u8>> {
        self.backend
            .load_private_ingress(invocation, reference)
            .ok()
            .flatten()
            .filter(|bytes| reference.matches(bytes))
    }

    pub(crate) fn prune_private_ingress(
        &mut self,
        invocation: super::InvocationId,
    ) -> Result<bool, ()> {
        match self.backend.delete_private_ingress(invocation) {
            Ok(deleted) => {
                self.private_ingress_retirement_debt.remove(&invocation);
                Ok(deleted)
            }
            Err(_) => {
                self.private_ingress_retirement_debt.insert(invocation);
                Err(())
            }
        }
    }

    /// Retire a private input after guest Apply committed. Failure is tracked
    /// as cleanup debt and must not rewrite the invocation's accepted result
    /// into a caller-visible failure.
    pub(crate) fn retire_private_ingress_after_commit(&mut self, invocation: super::InvocationId) {
        let _ = self.prune_private_ingress(invocation);
    }

    /// Persist producer-private Task records before the corresponding
    /// transition can enter a Raft log. Partial failure may leave harmless
    /// producer-local orphans, but can never make consensus state visible.
    pub(crate) fn persist_producer_records(
        &mut self,
        records: &[super::ProducedProvableRecordV2],
    ) -> Result<(), ()> {
        let mut identities = BTreeSet::new();
        for produced in records {
            if !identities.insert((produced.actor, produced.tag))
                || produced.entry.input.task_hash != produced.entry.record.task_hash
                || !produced.entry.record.io_consistent()
            {
                return Err(());
            }
            let encoded = produced.entry.encode();
            if crate::provable::ProofRecordEntry::decode(&encoded).as_ref() != Some(&produced.entry)
            {
                return Err(());
            }
            match self
                .backend
                .load_producer_record(produced.actor, &produced.tag)
                .map_err(|_| ())?
            {
                Some(existing) if existing == encoded => continue,
                Some(_) => return Err(()),
                None => {}
            }
            if !self
                .backend
                .commit_producer_record(produced.actor, &produced.tag, &encoded)
                .map_err(|_| ())?
            {
                return Err(());
            }
        }
        Ok(())
    }

    pub fn producer_record(&self, actor: ActorId, tag: &[u8; 32]) -> Option<Vec<u8>> {
        self.backend
            .load_producer_record(actor, tag)
            .ok()
            .flatten()
            .filter(|bytes| {
                crate::provable::ProofRecordEntry::decode(bytes)
                    .is_some_and(|entry| entry.encode().as_slice() == bytes.as_slice())
            })
    }

    pub fn prune_producer_record(&mut self, actor: ActorId, tag: &[u8; 32]) -> bool {
        self.backend
            .delete_producer_record(actor, tag)
            .unwrap_or(false)
    }

    /// Load and re-authorize an exact set of proof decisions under the
    /// currently installed verifier.
    ///
    /// Production registration uses this before exposing an existing local
    /// image. Snapshot/log catch-up verifies its ordered artifacts separately,
    /// so permanent reply admissions do not make snapshots retain proofs
    /// forever merely to repeat an already-finalized historical decision.
    fn revalidate_proofs(
        &mut self,
        requests: &[ProofVerificationRequestV2],
    ) -> Result<(), DecodeError> {
        let artifacts = requests
            .iter()
            .map(|request| {
                AttestationProofHostV2::proof_bytes(self, &request.proof_blob)
                    .ok_or(DecodeError::NonCanonical)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (request, proof) in requests.iter().zip(&artifacts) {
            if !AttestationProofHostV2::make_proof_available(self, request, proof) {
                return Err(DecodeError::NonCanonical);
            }
        }
        Ok(())
    }

    /// Establish durable provenance for the current exact image. A snapshot
    /// already carrying valid provenance came from a production-verifier
    /// commit and needs no pruned historical admission proofs on restart.
    /// Proofs referenced by live publications remain routing dependencies and
    /// are always loaded and reverified. An unmarked conformance image must be
    /// revalidated in full before the mark is persisted and the root can
    /// become routable.
    pub(crate) fn ensure_proof_verifier_provenance(&mut self) -> Result<(), DecodeError> {
        if self.local.proof_verifier.is_none() {
            return Err(DecodeError::NonCanonical);
        }
        if self.local.committed.has_proof_verifier_provenance() {
            let pending = self.local.committed.referenced_proof_verifications()?;
            return self.revalidate_proofs(&pending);
        }
        let history = self.local.committed.proof_verification_history()?;
        self.revalidate_proofs(&history)?;
        let mut replacement = self.local.committed.clone();
        replacement.seal_proof_verifier_provenance();
        self.backend
            .commit(&replacement.encode())
            .map_err(|_| DecodeError::NonCanonical)?;
        self.local.committed = replacement;
        Ok(())
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

/// Store equality describes the recoverable service-account image. The local
/// proof/private-witness inputs and credential, receipt, and install
/// allowlists are process-scoped host configuration and deliberately do not
/// participate in snapshots or equality.
impl PartialEq for LocalJamStoreV2 {
    fn eq(&self, other: &Self) -> bool {
        self.committed == other.committed
    }
}

impl Eq for LocalJamStoreV2 {}

impl LocalJamStoreV2 {
    pub const fn new() -> Self {
        Self {
            committed: LocalJamStoreSnapshotV2 {
                rows: BTreeMap::new(),
                blobs: BTreeMap::new(),
                programs: BTreeMap::new(),
                commit_sequence: 0,
                proof_verifier_provenance: None,
            },
            proof_blobs: BTreeMap::new(),
            private_witnesses: BTreeMap::new(),
            proof_verifier: None,
            proof_allowlist: BTreeSet::new(),
            role_credential_allowlist: BTreeSet::new(),
            upgrade_allowlist: BTreeSet::new(),
            receipt_allowlist: BTreeSet::new(),
            install_allowlist: BTreeSet::new(),
        }
    }

    /// Reopen one already-decoded committed service-account image.
    pub fn from_snapshot(snapshot: LocalJamStoreSnapshotV2) -> Self {
        Self {
            committed: snapshot,
            proof_blobs: BTreeMap::new(),
            private_witnesses: BTreeMap::new(),
            proof_verifier: None,
            proof_allowlist: BTreeSet::new(),
            role_credential_allowlist: BTreeSet::new(),
            upgrade_allowlist: BTreeSet::new(),
            receipt_allowlist: BTreeSet::new(),
            install_allowlist: BTreeSet::new(),
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

    /// Clone only committed state for in-process reconstruction. An active
    /// Accumulate transaction is owned by the service invocation and cannot be
    /// observed through this object.
    pub fn snapshot(&self) -> LocalJamStoreSnapshotV2 {
        self.committed.clone()
    }

    /// Canonical crash-recovery image. Receipt and install allowlists are host
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
            .or_else(|| self.proof_blobs.get(&reference.hash.0))
            .filter(|bytes| reference.matches(bytes))
            .map(Vec::as_slice)
    }

    pub fn program(&self, program: ProgramId) -> Option<&[u8]> {
        self.committed
            .programs
            .get(&program.0)
            .filter(|pvm| ProgramId::of_pvm(pvm) == program)
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

    /// Recover committed effects not yet acknowledged through guest
    /// Accumulate. Physical row order is stable across snapshot reopen.
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

    /// Recover finalized inbox admissions not yet consumed by actor
    /// execution. The original admission timeslot is guest-owned physical
    /// bookkeeping and survives a snapshot reopen.
    pub fn pending_inbox_calls(&self) -> Result<Vec<(super::CallId, u64)>, LocalStoreReadErrorV2> {
        let Some(header) = self.header()? else {
            return Ok(Vec::new());
        };
        let prefix = super::storage::delivery_storage_prefix();
        let mut pending = Vec::new();
        for (key, bytes) in self
            .committed
            .rows
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
        {
            let delivery = DeliveryRecordV2::decode(bytes)
                .map_err(|_| LocalStoreReadErrorV2::CorruptDelivery)?;
            if super::delivery_storage_key(delivery.call_id).as_slice() != key.as_slice()
                || delivery.receipt.service != header.service
                || delivery.receipt.consistency != header.consistency
            {
                return Err(LocalStoreReadErrorV2::CorruptDelivery);
            }
            if delivery.consumed || delivery.retired_at.is_some() {
                continue;
            }
            let message = self
                .state_row(header.service_root, &StateKeyV2::Inbox(delivery.call_id))?
                .map(|bytes| MessageRecordV2::decode(&bytes))
                .transpose()
                .map_err(|_| LocalStoreReadErrorV2::CorruptDelivery)?
                .ok_or(LocalStoreReadErrorV2::CorruptDelivery)?;
            if message.call_id != delivery.call_id {
                return Err(LocalStoreReadErrorV2::CorruptDelivery);
            }
            pending.push((delivery.call_id, delivery.logical_timeslot));
        }
        Ok(pending)
    }

    pub fn ingress_record(
        &self,
        invocation: super::InvocationId,
    ) -> Result<Option<IngressRecordV2>, LocalStoreReadErrorV2> {
        self.row(&super::ingress_storage_key(invocation))
            .map(IngressRecordV2::decode)
            .transpose()
            .map_err(|_| LocalStoreReadErrorV2::CorruptIngress)
            .and_then(|record| {
                if record
                    .as_ref()
                    .is_some_and(|record| record.ingress.invocation != invocation)
                {
                    Err(LocalStoreReadErrorV2::CorruptIngress)
                } else {
                    Ok(record)
                }
            })
    }

    /// Canonical invocation-id order for every guest-admitted direct call not
    /// yet consumed by an actor slice.
    pub fn pending_ingresses(&self) -> Result<Vec<DirectIngressV2>, LocalStoreReadErrorV2> {
        let prefix = super::storage::ingress_storage_prefix();
        let mut pending = Vec::new();
        for (key, bytes) in self
            .committed
            .rows
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
        {
            let record = IngressRecordV2::decode(bytes)
                .map_err(|_| LocalStoreReadErrorV2::CorruptIngress)?;
            if super::ingress_storage_key(record.ingress.invocation).as_slice() != key.as_slice() {
                return Err(LocalStoreReadErrorV2::CorruptIngress);
            }
            if !record.consumed {
                pending.push(record.ingress);
            }
        }
        Ok(pending)
    }

    /// Private-input ownership recovered from permanent guest ingress rows.
    /// Unconsumed rows retain and authenticate their sidecar; consumed rows
    /// are terminal evidence that any surviving sidecar must be retired.
    fn private_ingress_recovery(
        &self,
    ) -> Result<
        (
            Vec<(super::InvocationId, BlobRefV2)>,
            Vec<super::InvocationId>,
        ),
        LocalStoreReadErrorV2,
    > {
        let prefix = super::storage::ingress_storage_prefix();
        let mut retained = Vec::new();
        let mut terminal = Vec::new();
        for (key, bytes) in self
            .committed
            .rows
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
        {
            let record = IngressRecordV2::decode(bytes)
                .map_err(|_| LocalStoreReadErrorV2::CorruptIngress)?;
            let invocation = record.ingress.invocation;
            if super::ingress_storage_key(invocation).as_slice() != key.as_slice() {
                return Err(LocalStoreReadErrorV2::CorruptIngress);
            }
            let Some(reference) = record.ingress.private_arguments else {
                continue;
            };
            if record.consumed {
                terminal.push(invocation);
            } else {
                retained.push((invocation, reference));
            }
        }
        Ok((retained, terminal))
    }

    /// Load the caller-owned durable request which an accumulated reply must
    /// consume. Absence means this service has no pending route for the call.
    pub fn outbox_message(
        &self,
        call: super::CallId,
    ) -> Result<Option<MessageRecordV2>, LocalStoreReadErrorV2> {
        let Some(header) = self.header()? else {
            return Ok(None);
        };
        self.state_row(header.service_root, &StateKeyV2::Outbox(call))?
            .map(|bytes| {
                let message = MessageRecordV2::decode(&bytes)
                    .map_err(|_| LocalStoreReadErrorV2::CorruptReplyRoute)?;
                if message.call_id != call {
                    return Err(LocalStoreReadErrorV2::CorruptReplyRoute);
                }
                Ok(message)
            })
            .transpose()
    }

    /// Recover the guest-committed identity of an invocation for transport
    /// retry validation. The returned checkpoint is read-only authenticated
    /// service state; hosts cannot insert or rewrite it directly.
    pub fn workflow_checkpoint(
        &self,
        invocation: super::InvocationId,
    ) -> Result<Option<super::WorkflowCheckpointV2>, LocalStoreReadErrorV2> {
        let Some(header) = self.header()? else {
            return Ok(None);
        };
        self.state_row(header.service_root, &StateKeyV2::Workflow(invocation))?
            .map(|bytes| {
                super::WorkflowCheckpointV2::decode(&bytes)
                    .map_err(|_| LocalStoreReadErrorV2::CorruptStateTree)
            })
            .transpose()
    }

    /// Recover the exact guest-written accumulation receipt for a completed
    /// input. Receipts are durable bookkeeping, unlike transient publication
    /// rows, so platform consumers can validate an invocation retry after its
    /// effects were acknowledged.
    pub fn accumulation_receipt(
        &self,
        input: super::WorkInputIdV2,
    ) -> Result<Option<super::AccumulationReceiptV2>, LocalStoreReadErrorV2> {
        self.row(&super::receipt_storage_key(input))
            .map(super::AccumulationReceiptV2::decode)
            .transpose()
            .map_err(|_| LocalStoreReadErrorV2::CorruptReceipt)
            .and_then(|receipt| {
                if receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.checkpoint != input.workflow_step)
                {
                    Err(LocalStoreReadErrorV2::CorruptReceipt)
                } else {
                    Ok(receipt)
                }
            })
    }

    /// Recover the guest-owned proof that this exact transition had the
    /// single-slice external-effect shape required for a role assertion.
    /// Unlike its publication row, the eligibility record survives effect
    /// acknowledgement.
    pub fn role_assertion_eligibility(
        &self,
        input: super::WorkInputIdV2,
    ) -> Result<Option<super::RoleAssertionEligibilityV2>, LocalStoreReadErrorV2> {
        self.row(&super::role_assertion_eligibility_storage_key(input))
            .map(super::RoleAssertionEligibilityV2::decode)
            .transpose()
            .map_err(|_| LocalStoreReadErrorV2::CorruptReceipt)
    }

    /// Recover the exact guest-committed outcome for one expired durable
    /// call. The row remains after continuation completion so retries can be
    /// classified without reconstructing a process-local timer.
    pub fn call_expiration(
        &self,
        call: super::CallId,
    ) -> Result<Option<AccumulatedTimeoutV2>, LocalStoreReadErrorV2> {
        self.row(&super::call_expiration_storage_key(call))
            .map(AccumulatedTimeoutV2::decode)
            .transpose()
            .map_err(|_| LocalStoreReadErrorV2::CorruptExpiration)
            .and_then(|timeout| {
                if timeout
                    .as_ref()
                    .is_some_and(|timeout| timeout.expiration.timeout.call_id != call)
                {
                    Err(LocalStoreReadErrorV2::CorruptExpiration)
                } else {
                    Ok(timeout)
                }
            })
    }

    /// Enumerate every durable timeout outcome in canonical CallId order.
    /// Outcomes outlive deadline rows and continuation completion so restart
    /// orchestration can rediscover an expiration committed just before a
    /// crash. Callers must still check whether its workflow remains pending.
    pub fn call_expirations(&self) -> Result<Vec<AccumulatedTimeoutV2>, LocalStoreReadErrorV2> {
        let prefix = super::storage::call_expiration_storage_prefix();
        self.committed
            .rows
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, bytes)| {
                let timeout = AccumulatedTimeoutV2::decode(bytes)
                    .map_err(|_| LocalStoreReadErrorV2::CorruptExpiration)?;
                if super::call_expiration_storage_key(timeout.expiration.timeout.call_id).as_slice()
                    != key.as_slice()
                {
                    return Err(LocalStoreReadErrorV2::CorruptExpiration);
                }
                Ok(timeout)
            })
            .collect()
    }

    /// Enumerate deadline-bearing suspended calls from guest-owned physical
    /// bookkeeping. Every row is cross-checked against the authoritative
    /// outbox before it is exposed to restart orchestration.
    pub fn pending_call_deadlines(
        &self,
    ) -> Result<Vec<super::PendingCallDeadlineV2>, LocalStoreReadErrorV2> {
        let Some(header) = self.header()? else {
            return Ok(Vec::new());
        };
        let prefix = super::storage::pending_call_deadline_storage_prefix();
        self.committed
            .rows
            .range(prefix.to_vec()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, bytes)| {
                let deadline = super::PendingCallDeadlineV2::decode(bytes)
                    .map_err(|_| LocalStoreReadErrorV2::CorruptPendingDeadline)?;
                if super::pending_call_deadline_storage_key(deadline.call_id).as_slice()
                    != key.as_slice()
                {
                    return Err(LocalStoreReadErrorV2::CorruptPendingDeadline);
                }
                let message = self
                    .state_row(header.service_root, &StateKeyV2::Outbox(deadline.call_id))?
                    .map(|bytes| MessageRecordV2::decode(&bytes))
                    .transpose()
                    .map_err(|_| LocalStoreReadErrorV2::CorruptPendingDeadline)?
                    .ok_or(LocalStoreReadErrorV2::CorruptPendingDeadline)?;
                if message.call_id != deadline.call_id
                    || message.caller_invocation != deadline.caller_invocation
                    || message.deadline_timeslot != Some(deadline.deadline_timeslot)
                {
                    return Err(LocalStoreReadErrorV2::CorruptPendingDeadline);
                }
                Ok(deadline)
            })
            .collect()
    }

    /// Recover a previously committed reply admission and cross-check it
    /// against the exact work-input dedup row written in the same guest
    /// transaction.
    pub fn reply_admission(
        &self,
        call: super::CallId,
    ) -> Result<Option<(ReplyAdmissionRecordV2, AccumulationReceiptV2)>, LocalStoreReadErrorV2>
    {
        let Some(bytes) = self.row(&super::reply_admission_storage_key(call)) else {
            return Ok(None);
        };
        let admission = ReplyAdmissionRecordV2::decode(bytes)
            .map_err(|_| LocalStoreReadErrorV2::CorruptReplyRoute)?;
        if admission.call_id != call {
            return Err(LocalStoreReadErrorV2::CorruptReplyRoute);
        }
        let dedup_bytes = self
            .row(&super::dedup_storage_key(admission.input))
            .ok_or(LocalStoreReadErrorV2::CorruptReplyRoute)?;
        let dedup = DedupRecordV2::decode(dedup_bytes)
            .map_err(|_| LocalStoreReadErrorV2::CorruptReplyRoute)?;
        let header = self
            .header()?
            .ok_or(LocalStoreReadErrorV2::CorruptReplyRoute)?;
        if dedup.input != admission.input
            || dedup.work_hash != admission.work_hash
            || dedup.receipt.service != header.service
        {
            return Err(LocalStoreReadErrorV2::CorruptReplyRoute);
        }
        Ok(Some((admission, dedup.receipt)))
    }

    /// Make an installation input available to guest Accumulate. This is a
    /// content-addressed import operation, not a service-state mutation.
    pub fn import_blob(&mut self, bytes: Vec<u8>) -> BlobRefV2 {
        let reference = BlobRefV2::of_bytes(&bytes);
        self.committed.blobs.insert(reference.hash.0, bytes);
        reference
    }

    /// Supply one invocation-private role witness to Refine/proving without
    /// making it part of service state. Reopening a snapshot intentionally
    /// drops this process-local input.
    pub fn import_private_witness(&mut self, bytes: Vec<u8>) -> BlobRefV2 {
        let reference = BlobRefV2::of_bytes(&bytes);
        self.private_witnesses.insert(reference.hash.0, bytes);
        reference
    }

    pub fn private_witness(&self, reference: &BlobRefV2) -> Option<&[u8]> {
        self.private_witnesses
            .get(&reference.hash.0)
            .filter(|bytes| reference.matches(bytes))
            .map(Vec::as_slice)
    }

    /// Make exact canonical actor code available to guest Accumulate.
    ///
    /// Program availability is part of the cloned service image, so reopening
    /// that complete image cannot turn a previously valid deployment into a
    /// node-local cache miss.
    pub fn import_program(&mut self, pvm: Vec<u8>) -> ProgramId {
        let program = ProgramId::of_pvm(&pvm);
        self.committed.programs.insert(program.0, pvm);
        program
    }

    /// Configure the conformance host to accept one exact proof request.
    ///
    /// Production hosts replace this process-local allowlist with their
    /// consensus-pinned proof verifier. It is excluded from persisted state.
    pub fn allow_proof(&mut self, request: &ProofVerificationRequestV2) {
        if self.proof_verifier.is_none() {
            self.proof_allowlist.insert(request.hash());
        }
    }

    /// Install the verifier used by every later proof hydration and IC-5
    /// transaction. Installing a verifier clears conformance grants so bytes
    /// accepted under the local seam cannot survive a production cutover.
    pub fn install_proof_verifier<F>(&mut self, verifier: F)
    where
        F: Fn(&ProofVerificationRequestV2, &[u8]) -> bool + Send + Sync + 'static,
    {
        self.install_proof_verifier_arc(Arc::new(verifier));
    }

    pub(crate) fn install_proof_verifier_arc(&mut self, verifier: Arc<ProofVerifierFnV2>) {
        self.proof_allowlist.clear();
        self.proof_verifier = Some(verifier);
    }

    fn proof_is_accepted(&self, request: &ProofVerificationRequestV2, proof: &[u8]) -> bool {
        request.proof_blob.matches(proof)
            && self
                .proof_verifier
                .as_ref()
                .is_none_or(|verifier| verifier(request, proof))
    }

    fn record_proof_available(&mut self, request: &ProofVerificationRequestV2, proof: &[u8]) {
        self.proof_blobs
            .insert(request.proof_blob.hash.0, proof.to_vec());
        self.proof_allowlist.insert(request.hash());
    }

    /// Configure the conformance authority to accept one exact disclosed
    /// role credential verification request.
    pub fn allow_role_credential(&mut self, request: &RoleCredentialVerificationRequestV2) {
        self.role_credential_allowlist.insert(request.hash());
    }

    /// Authorize one exact actor upgrade. The replacement program is supplied
    /// separately as content-addressed request availability and must be
    /// present in the staged image before guest validation can accept it.
    pub fn allow_upgrade(&mut self, upgrade: &ActorUpgradeV2) -> bool {
        self.upgrade_allowlist.insert(upgrade.hash());
        true
    }

    /// Configure the conformance host to accept one exact finalized receipt.
    ///
    /// Production hosts replace this process-local allowlist with the
    /// consensus receipt/finality verifier required by the runtime cutover.
    pub fn allow_receipt(&mut self, request: &ReceiptVerificationRequestV2) {
        self.receipt_allowlist.insert(request.hash());
    }

    /// Authorize one exact canonical genesis for physical guest Install.
    ///
    /// This conformance policy is process-local and deliberately excluded
    /// from the recoverable service image. Production hosts implement the
    /// same guest boundary from consensus-authoritative deployment state.
    pub fn allow_install(&mut self, genesis: &ServiceGenesisV2) {
        self.install_allowlist.insert(install_hash(genesis));
    }
}

impl AttestationProofHostV2 for LocalJamStoreV2 {
    fn make_proof_available(&mut self, request: &ProofVerificationRequestV2, proof: &[u8]) -> bool {
        if !self.proof_is_accepted(request, proof) {
            return false;
        }
        self.record_proof_available(request, proof);
        true
    }

    fn proof_bytes(&self, reference: &BlobRefV2) -> Option<Vec<u8>> {
        self.proof_blobs
            .get(&reference.hash.0)
            .filter(|bytes| reference.matches(bytes))
            .cloned()
    }

    fn requires_proof_verifier_provenance(&self) -> bool {
        self.proof_verifier.is_some()
    }
}

impl super::ReceiptVerificationHostV2 for LocalJamStoreV2 {
    fn make_receipt_available(&mut self, request: &ReceiptVerificationRequestV2) -> bool {
        self.allow_receipt(request);
        true
    }
}

impl<B> super::ReceiptVerificationHostV2 for DurableJamStoreV2<B> {
    fn make_receipt_available(&mut self, request: &ReceiptVerificationRequestV2) -> bool {
        super::ReceiptVerificationHostV2::make_receipt_available(&mut self.local, request)
    }
}

impl<B: ProofArtifactStoreV2> AttestationProofHostV2 for DurableJamStoreV2<B> {
    fn make_proof_available(&mut self, request: &ProofVerificationRequestV2, proof: &[u8]) -> bool {
        if !self.local.proof_is_accepted(request, proof)
            || self
                .backend
                .commit_proof(&request.proof_blob, proof)
                .is_err()
        {
            return false;
        }
        self.local.record_proof_available(request, proof);
        true
    }

    fn proof_bytes(&self, reference: &BlobRefV2) -> Option<Vec<u8>> {
        self.local.proof_bytes(reference).or_else(|| {
            self.backend
                .load_proof(reference)
                .ok()
                .flatten()
                .filter(|bytes| reference.matches(bytes))
        })
    }

    fn requires_proof_verifier_provenance(&self) -> bool {
        self.local.proof_verifier.is_some()
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
    logical_timeslot: Option<u64>,
    proof_blobs: BTreeMap<[u8; 32], Vec<u8>>,
    proof_allowlist: BTreeSet<super::Hash>,
    role_credential_allowlist: BTreeSet<super::Hash>,
    upgrade_allowlist: BTreeSet<super::Hash>,
    receipt_allowlist: BTreeSet<super::Hash>,
    install_allowlist: BTreeSet<super::Hash>,
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

    fn role_credential_verification_status(&self, bytes: &[u8]) -> u64 {
        use crate::abi::error;

        let Ok(request) = RoleCredentialVerificationRequestV2::decode(bytes) else {
            // Guest-supplied verifier input is untrusted. A malformed request
            // is an authorization denial, not a host failure: returning a
            // hard error here would prevent a replicated apply cursor from
            // advancing past a deterministically invalid entry.
            return error::HOST_NONE;
        };
        if self.role_credential_allowlist.contains(&request.hash()) {
            error::HOST_OK
        } else {
            error::HOST_NONE
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
            hostcall::ACCUMULATION_TIMESLOT => {
                Ok([self.logical_timeslot.unwrap_or(error::HOST_NONE), 0])
            }
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
            hostcall::PROGRAM_LOOKUP => {
                let program: [u8; 32] = Self::read_guest_bytes(kernel, registers[7], 32, slot)?
                    .try_into()
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                Ok([
                    if self
                        .staged
                        .programs
                        .get(&program)
                        .is_some_and(|pvm| ProgramId::of_pvm(pvm).0 == program)
                    {
                        error::HOST_OK
                    } else {
                        error::HOST_NONE
                    },
                    0,
                ])
            }
            hostcall::PROOF_VERIFY => {
                let bytes = Self::read_guest_bytes(kernel, registers[7], registers[8], slot)?;
                let request = ProofVerificationRequestV2::decode(&bytes)
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let proof_available = self
                    .proof_blobs
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
            hostcall::ROLE_CREDENTIAL_VERIFY => {
                let bytes = Self::read_guest_bytes(kernel, registers[7], registers[8], slot)?;
                Ok([self.role_credential_verification_status(&bytes), 0])
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
            hostcall::INSTALL_AUTH_VERIFY => {
                let bytes = Self::read_guest_bytes(kernel, registers[7], registers[8], slot)?;
                let request = super::AccumulateRequestV2::decode(&bytes)
                    .map_err(|_| ServicePvmErrorV2::AccumulateHostRejected(slot))?;
                let authorized = match request {
                    super::AccumulateRequestV2::Install(genesis) => {
                        self.install_allowlist.contains(&install_hash(&genesis))
                    }
                    super::AccumulateRequestV2::UpgradeActor(upgrade) => {
                        self.upgrade_allowlist.contains(&upgrade.hash())
                            && self
                                .staged
                                .programs
                                .contains_key(&upgrade.replacement_program.0)
                    }
                    _ => false,
                };
                Ok([
                    if authorized {
                        error::HOST_OK
                    } else {
                        error::HOST_WHAT
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
        self.begin_at(None)
    }

    fn begin_at(
        &mut self,
        logical_timeslot: Option<u64>,
    ) -> Result<Self::Transaction, ServicePvmErrorV2> {
        self.begin_at_with_availability(logical_timeslot, &[], &[])
    }

    fn begin_at_with_availability(
        &mut self,
        logical_timeslot: Option<u64>,
        programs: &[super::ImportedProgramV2],
        blobs: &[super::ImportedBlobV2],
    ) -> Result<Self::Transaction, ServicePvmErrorV2> {
        let mut staged = self.committed.clone();
        for program in programs {
            if super::ProgramId::of_pvm(&program.pvm) != program.program
                || staged
                    .programs
                    .get(&program.program.0)
                    .is_some_and(|bytes| bytes != &program.pvm)
            {
                return Err(ServicePvmErrorV2::AccumulateHostRejected(
                    crate::abi::hostcall::PROGRAM_LOOKUP as u8,
                ));
            }
            staged
                .programs
                .insert(program.program.0, program.pvm.clone());
        }
        for blob in blobs {
            if !blob.reference.matches(&blob.bytes)
                || staged
                    .blobs
                    .get(&blob.reference.hash.0)
                    .is_some_and(|bytes| bytes != &blob.bytes)
            {
                return Err(ServicePvmErrorV2::AccumulateHostRejected(
                    crate::abi::hostcall::PREIMAGE_PROVIDE as u8,
                ));
            }
            staged
                .blobs
                .insert(blob.reference.hash.0, blob.bytes.clone());
        }
        Ok(LocalJamTransactionV2 {
            staged,
            logical_timeslot,
            proof_blobs: self.proof_blobs.clone(),
            proof_allowlist: self.proof_allowlist.clone(),
            role_credential_allowlist: self.role_credential_allowlist.clone(),
            upgrade_allowlist: self.upgrade_allowlist.clone(),
            receipt_allowlist: self.receipt_allowlist.clone(),
            install_allowlist: self.install_allowlist.clone(),
        })
    }

    fn commit(&mut self, mut transaction: Self::Transaction) -> Result<(), ServicePvmErrorV2> {
        transaction.staged.commit_sequence = self
            .committed
            .commit_sequence
            .checked_add(1)
            .ok_or(ServicePvmErrorV2::AccumulateCommitRejected)?;
        transaction.staged.proof_verifier_provenance = None;
        if self.proof_verifier.is_some() {
            transaction.staged.seal_proof_verifier_provenance();
        }
        self.committed = transaction.staged;
        Ok(())
    }
}

impl<B: CommittedImageStoreV2> AccumulateProtocolHostV2 for DurableJamStoreV2<B> {
    type Transaction = LocalJamTransactionV2;

    fn begin(&mut self) -> Result<Self::Transaction, ServicePvmErrorV2> {
        self.local.begin()
    }

    fn begin_at(
        &mut self,
        logical_timeslot: Option<u64>,
    ) -> Result<Self::Transaction, ServicePvmErrorV2> {
        self.local.begin_at(logical_timeslot)
    }

    fn begin_at_with_availability(
        &mut self,
        logical_timeslot: Option<u64>,
        programs: &[super::ImportedProgramV2],
        blobs: &[super::ImportedBlobV2],
    ) -> Result<Self::Transaction, ServicePvmErrorV2> {
        self.local
            .begin_at_with_availability(logical_timeslot, programs, blobs)
    }

    fn commit(&mut self, mut transaction: Self::Transaction) -> Result<(), ServicePvmErrorV2> {
        transaction.staged.commit_sequence = self
            .local
            .committed
            .commit_sequence
            .checked_add(1)
            .ok_or(ServicePvmErrorV2::AccumulateCommitRejected)?;
        transaction.staged.proof_verifier_provenance = None;
        if self.local.proof_verifier.is_some() {
            transaction.staged.seal_proof_verifier_provenance();
        }
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

    impl ProofArtifactStoreV2 for TestImageStore {
        type Error = InjectedFailure;

        fn load_proof(&self, _reference: &BlobRefV2) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(None)
        }

        fn commit_proof(
            &mut self,
            _reference: &BlobRefV2,
            _proof: &[u8],
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn reconcile_private_ingresses(
            &mut self,
            retained: &[(super::super::InvocationId, BlobRefV2)],
            _terminal: &[super::super::InvocationId],
        ) -> Result<(), Self::Error> {
            if retained.is_empty() {
                Ok(())
            } else {
                Err(InjectedFailure)
            }
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
                gas_schedule: super::super::GasScheduleV2::new(1_000_000_000, 5_000_000_000),
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
    fn proof_artifacts_never_enter_the_recoverable_service_image() {
        let mut store = LocalJamStoreV2::new();
        let proof = vec![0xA5; 1024 * 1024];
        let proof_blob = BlobRefV2::of_bytes(&proof);
        let request = ProofVerificationRequestV2 {
            actor_program: ProgramId([1; 32]),
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
            statement: super::super::Hash([2; 32]),
            trace: super::super::Hash([3; 32]),
            proof_blob: proof_blob.clone(),
        };
        let before = store.snapshot_bytes();

        assert!(store.make_proof_available(&request, &proof));
        assert_eq!(store.snapshot_bytes(), before);
        assert_eq!(store.blob_count(), 0);

        let transaction = store.begin().unwrap();
        assert_eq!(
            transaction
                .proof_blobs
                .get(&proof_blob.hash.0)
                .map(Vec::as_slice),
            Some(proof.as_slice())
        );
    }

    #[test]
    fn installed_proof_verifier_cannot_be_bypassed_by_conformance_grants() {
        let mut store = LocalJamStoreV2::new();
        let proof = b"verified proof artifact".to_vec();
        let proof_blob = BlobRefV2::of_bytes(&proof);
        let request = ProofVerificationRequestV2 {
            actor_program: ProgramId([1; 32]),
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
            statement: super::super::Hash([2; 32]),
            trace: super::super::Hash([3; 32]),
            proof_blob: proof_blob.clone(),
        };

        store.allow_proof(&request);
        store.install_proof_verifier(|_, _| false);
        store.allow_proof(&request);
        assert!(!store.make_proof_available(&request, &proof));
        assert_eq!(store.proof_bytes(&proof_blob), None);

        let expected_request = request.clone();
        let expected_proof = proof.clone();
        store.install_proof_verifier(move |candidate, bytes| {
            candidate == &expected_request && bytes == expected_proof
        });
        assert!(store.make_proof_available(&request, &proof));
        assert_eq!(store.proof_bytes(&proof_blob), Some(proof));
    }

    #[test]
    fn private_role_witnesses_never_enter_the_recoverable_service_image() {
        let mut store = LocalJamStoreV2::new();
        let witness = b"invocation-private credential witness".to_vec();
        let before = store.snapshot_bytes();

        let reference = store.import_private_witness(witness.clone());
        assert_eq!(store.private_witness(&reference), Some(witness.as_slice()));
        assert_eq!(store.snapshot_bytes(), before);
        assert_eq!(store.blob_count(), 0);

        let reopened = LocalJamStoreV2::from_snapshot(store.snapshot());
        assert_eq!(reopened.private_witness(&reference), None);
        assert_eq!(reopened, store);
    }

    #[test]
    fn malformed_role_verification_requests_are_clean_denials() {
        let mut store = LocalJamStoreV2::new();
        let transaction = store.begin().unwrap();

        assert_eq!(
            transaction.role_credential_verification_status(b"not a canonical request"),
            crate::abi::error::HOST_NONE
        );
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
        let pvm = b"canonical actor program".to_vec();
        let program = ProgramId::of_pvm(&pvm);
        transaction.staged.programs.insert(program.0, pvm);
        store.commit(transaction).unwrap();

        assert_eq!(store.commit_sequence(), 1);
        assert_eq!(store.row(b"header"), Some(b"new root".as_slice()));
        assert_eq!(
            store.blob(&reference),
            Some(b"continuation page".as_slice())
        );
        assert_eq!(
            store.program(program),
            Some(b"canonical actor program".as_slice())
        );

        store.receipt_allowlist.insert(crate::v2::Hash([7; 32]));
        let reopened = LocalJamStoreV2::from_snapshot(store.snapshot());
        assert!(reopened.receipt_allowlist.is_empty());
        assert!(!store.receipt_allowlist.is_empty());
        assert_eq!(reopened, store);
    }

    #[test]
    fn committed_snapshot_wire_restores_and_rejects_identity_drift() {
        let mut store = LocalJamStoreV2::new();
        let blob = store.import_blob(b"continuation page".to_vec());
        let program = store.import_program(b"canonical actor pvm".to_vec());
        let mut transaction = store.begin().unwrap();
        transaction.staged.rows.insert(
            super::super::header_storage_key().to_vec(),
            valid_header().encode(),
        );
        store.commit(transaction).unwrap();

        store.receipt_allowlist.insert(crate::v2::Hash([7; 32]));
        let bytes = store.snapshot_bytes();
        assert_eq!(
            bytes,
            store.snapshot_bytes(),
            "snapshot wire is deterministic"
        );
        let restarted = LocalJamStoreV2::from_snapshot_bytes(&bytes).unwrap();
        assert_eq!(restarted, store);
        assert!(restarted.receipt_allowlist.is_empty());
        assert_eq!(restarted.blob(&blob), Some(b"continuation page".as_slice()));
        assert_eq!(
            restarted.program(program),
            Some(b"canonical actor pvm".as_slice())
        );

        let mut forged_provenance = store.snapshot();
        forged_provenance.proof_verifier_provenance = Some(super::super::Hash([0xFA; 32]));
        assert_eq!(
            LocalJamStoreSnapshotV2::decode(&forged_provenance.encode()),
            Err(DecodeError::NonCanonical),
            "verifier provenance is bound to the exact durable image"
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

        let mut missing_header = store.snapshot();
        missing_header
            .rows
            .remove(super::super::header_storage_key());
        assert_eq!(
            LocalJamStoreSnapshotV2::decode(&missing_header.encode()),
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
        let proof = b"durable proof side-CAS".to_vec();
        let proof_blob = BlobRefV2::of_bytes(&proof);
        let private_invocation = super::super::InvocationId([40; 32]);
        let legacy_payload = b"operator-private invocation arguments";
        let legacy_payload_reference = BlobRefV2::of_bytes(legacy_payload);
        let mut private_arguments = LEGACY_PRIVATE_INGRESS_ARTIFACT_MAGIC.to_vec();
        private_arguments.extend_from_slice(&legacy_payload_reference.hash.0);
        private_arguments.extend_from_slice(&legacy_payload_reference.len.to_le_bytes());
        private_arguments.extend_from_slice(legacy_payload);
        let private_reference = store
            .persist_private_ingress(private_invocation, &private_arguments)
            .unwrap();
        let header = store.header().unwrap().unwrap();
        let ingress = DirectIngressV2 {
            service: header.service.clone(),
            invocation: private_invocation,
            logical_timeslot: 1,
            target: ActorId([39; 32]),
            method: "private".into(),
            arguments: Vec::new(),
            private_arguments: Some(private_reference.clone()),
            origin: super::super::Origin::Anonymous,
            authorization: super::super::AuthorizationEvidenceV2::Public,
            imported_blobs: Vec::new(),
            proof_requested: false,
            base: super::super::ConsistencyBaseV2::Linear {
                revision: header.revision,
                state_root: header.state_root.unwrap(),
            },
            base_causal_height: None,
            crdt_change: None,
        };
        let receipt = AccumulationReceiptV2 {
            service: header.service,
            accepted_transition: ingress.commitment(),
            reply_commitment: None,
            outbox_commitment: None,
            resulting_state_root: header.state_root,
            resulting_crdt_heads: Vec::new(),
            sequence: header.revision,
            checkpoint: 0,
            consistency: super::super::ConsistencyModeV2::Local,
        };
        let mut transaction = store.begin().unwrap();
        transaction.staged.rows.insert(
            super::super::ingress_storage_key(private_invocation),
            IngressRecordV2 {
                ingress: ingress.clone(),
                consumed: false,
                receipt,
            }
            .encode(),
        );
        store.commit(transaction).unwrap();
        let orphan_invocation = super::super::InvocationId([38; 32]);
        let orphan_arguments = b"crash before guest admission".to_vec();
        let orphan_reference = store
            .persist_private_ingress(orphan_invocation, &orphan_arguments)
            .unwrap();
        let replicated_invocation = super::super::InvocationId([37; 32]);
        let replicated_arguments = b"acknowledged Raft pre-admission input".to_vec();
        let replicated_reference = store
            .persist_replicated_private_ingress(replicated_invocation, &replicated_arguments)
            .unwrap();
        let verification = ProofVerificationRequestV2 {
            actor_program: ProgramId([41; 32]),
            execution_semantics: super::super::EXECUTION_SEMANTICS_ID,
            statement: super::super::Hash([42; 32]),
            trace: super::super::Hash([43; 32]),
            proof_blob: proof_blob.clone(),
        };
        assert!(store.make_proof_available(&verification, &proof));
        let actor = ActorId([44; 32]);
        let tag = [45; 32];
        let mut record = crate::provable::ProvableRecord {
            task_hash: [46; 32],
            anchor_kind: 1,
            anchor: [47; 32],
            transition_digest: [48; 32],
            reply: b"private Task reply".to_vec(),
            io_hash: [0; 32],
            app_public: b"public Task binding".to_vec(),
            catalog_name: alloc::string::String::new(),
            catalog_version: 0,
        };
        record.io_hash = crate::zk::compute_io_hash(&record.public_prime(), &record.reply);
        let entry = crate::provable::ProofRecordEntry {
            input: crate::provable::ProvableInput {
                task_hash: record.task_hash,
                witness_bytes: b"producer-only witness".to_vec(),
            },
            record,
        };
        store
            .persist_producer_records(&[super::super::ProducedProvableRecordV2 {
                actor,
                tag,
                entry: entry.clone(),
            }])
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let private_path = store.backend.private_ingress_path(private_invocation);
            assert_eq!(
                std::fs::metadata(private_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "private invocation inputs must be owner-only",
            );
            let record_path = store.backend.producer_record_path(actor, &tag);
            assert_eq!(
                std::fs::metadata(record_path).unwrap().permissions().mode() & 0o777,
                0o600,
                "producer witness records must be owner-only",
            );
        }
        let expected = store.snapshot();
        let abandoned_temporary = store
            .backend
            .private_ingress_directory()
            .join("abandoned.v2-next");
        std::fs::write(&abandoned_temporary, b"partial private input").unwrap();
        std::fs::write(
            store
                .backend
                .legacy_private_ingress_path(private_invocation),
            &private_arguments,
        )
        .unwrap();
        std::fs::remove_file(store.backend.private_ingress_path(private_invocation)).unwrap();
        drop(store);

        let mut restarted = DurableJamStoreV2::open(FileCommittedImageStoreV2::new(&path)).unwrap();
        assert_eq!(restarted.snapshot(), expected);
        assert!(
            !expected
                .encode()
                .windows(private_arguments.len())
                .any(|window| window == private_arguments),
            "private invocation input must stay outside the service image",
        );
        assert!(
            !expected
                .encode()
                .windows(orphan_arguments.len())
                .any(|window| window == orphan_arguments),
            "pre-admission private input must stay outside the service image",
        );
        assert_eq!(
            restarted.private_ingress(private_invocation, &private_reference),
            Some(private_arguments.clone()),
            "startup migrates Batch 60 raw input owned by an unconsumed guest ingress",
        );
        assert_eq!(
            restarted.private_ingress(orphan_invocation, &orphan_reference),
            None,
            "startup retires a Local crash-before-admission orphan",
        );
        assert_eq!(
            restarted.private_ingress(replicated_invocation, &replicated_reference),
            Some(replicated_arguments.clone()),
            "startup retains an acknowledged replicated pre-admission input",
        );
        assert!(
            std::fs::read(restarted.backend.private_ingress_path(private_invocation))
                .unwrap()
                .starts_with(PRIVATE_INGRESS_ARTIFACT_MAGIC)
        );
        assert!(!abandoned_temporary.exists());
        assert_eq!(restarted.proof_bytes(&proof_blob), Some(proof));
        assert_eq!(restarted.producer_record(actor, &tag), Some(entry.encode()));
        assert!(restarted.prune_producer_record(actor, &tag));
        assert_eq!(restarted.producer_record(actor, &tag), None);
        assert!(!path.with_file_name("service.v2.v2-next").exists());
        assert!(path.with_file_name("service.v2.proofs").is_dir());
        assert!(path.with_file_name("service.v2.private-inputs").is_dir());
        assert!(path.with_file_name("service.v2.records").is_dir());

        let mut transaction = restarted.begin().unwrap();
        let mut consumed = restarted
            .ingress_record(private_invocation)
            .unwrap()
            .unwrap();
        consumed.consumed = true;
        transaction.staged.rows.insert(
            super::super::ingress_storage_key(private_invocation),
            consumed.encode(),
        );
        restarted.commit(transaction).unwrap();
        let (_, backend) = restarted.into_parts();
        let mut restarted = DurableJamStoreV2::open(backend).unwrap();
        assert_eq!(
            restarted.private_ingress(private_invocation, &private_reference),
            None,
            "a consumed guest ingress retires a surviving terminal artifact on restart",
        );
        assert_eq!(
            restarted.private_ingress(replicated_invocation, &replicated_reference),
            Some(replicated_arguments),
        );
        assert!(
            restarted
                .prune_private_ingress(replicated_invocation)
                .unwrap()
        );
        drop(restarted);

        std::fs::write(&path, b"legacy-or-corrupt-image").unwrap();
        assert!(matches!(
            DurableJamStoreV2::open(FileCommittedImageStoreV2::new(&path)),
            Err(DurableStoreOpenErrorV2::InvalidSnapshot(
                DecodeError::InvalidTag
            ))
        ));

        std::fs::remove_dir_all(directory).unwrap();
    }
}
