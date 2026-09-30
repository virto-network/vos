//! Streaming storage closure codec for detached, certified maintenance export.
//!
//! A decoded/staged archive is neither common-checkpoint authority nor a root
//! availability capability. The host must independently authenticate its QC,
//! rebind destination metadata, audit the complete closure, and activate it
//! through the existing journal/ledger recovery protocol.

use super::*;
use std::io::{Read, Write};

const MAGIC: &[u8; 4] = b"AXJ1";
const ARCHIVE_DOMAIN: &[u8] = b"vos/agent/external-journal-archive/v1";
const KEYS_DOMAIN: &[u8] = b"vos/agent/external-journal-archive/keys/v1";
const OBJECT: u8 = 0;
const BLOB: u8 = 1;
const END: u8 = 2;
const FOOTER_BYTES: u64 = 1 + 4 * 8 + 2 * 32;

/// Independent maintenance quotas, not AJB1's whole-image allocation limits.
/// Count limits bound the eventual ID-only mark; no codec allocation is based
/// on a record count. Wire bytes include framing, header and footer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ExternalArchiveLimits {
    pub(crate) max_objects: usize,
    pub(crate) max_blobs: usize,
    pub(crate) max_history_nodes: usize,
    pub(crate) max_wire_bytes: u64,
}

impl ExternalArchiveLimits {
    pub(super) fn validate(self) -> Result<(), JournalStoreError> {
        if self.max_objects == 0
            || self.max_blobs == 0
            || self.max_history_nodes == 0
            || self.max_history_nodes > self.max_objects
            || self.max_wire_bytes < FOOTER_BYTES + 40
        {
            return Err(JournalStoreError::LimitExceeded);
        }
        Ok(())
    }
}

/// Source metadata only. In particular, a foreign predecessor is never sent
/// to an immutable-staging callback which could install local head history.
#[derive(Clone, Debug)]
pub(crate) struct ExternalArchiveReport {
    pub(crate) source_heads: JournalHeads,
    pub(crate) source_predecessor: Option<JournalHeads>,
    pub(crate) objects: u64,
    pub(crate) blobs: u64,
    pub(crate) history_nodes: u64,
    pub(crate) wire_bytes: u64,
    pub(crate) keys: Hash,
    pub(crate) identity: Hash,
}

/// One already class-bound, content-checked payload. The callback may stage
/// it immutably, but cannot receive a Heads record or a publication token.
pub(crate) enum ExternalArchiveRecord<'a> {
    Object {
        class: JournalStorageClass,
        id: [u8; 32],
        bytes: &'a [u8],
    },
    Blob {
        class: JournalBlobClass,
        reference: &'a BlobRef,
        bytes: &'a [u8],
    },
}

fn hash_state(domain: &[u8]) -> blake2b_simd::State {
    let mut state = blake2b_simd::Params::new().hash_length(32).to_state();
    state.update(domain);
    state
}

fn finish_hash(state: &blake2b_simd::State) -> Hash {
    let mut bytes = [0; 32];
    bytes.copy_from_slice(state.finalize().as_bytes());
    Hash(bytes)
}

fn object_key(state: &mut blake2b_simd::State, class: JournalStorageClass, id: &[u8; 32]) {
    state.update(&[OBJECT, class as u8]);
    state.update(id);
}

fn blob_key(state: &mut blake2b_simd::State, class: JournalBlobClass, reference: &BlobRef) {
    state.update(&[BLOB, class as u8]);
    state.update(&reference.hash.0);
    state.update(&reference.len.to_le_bytes());
}

fn validate_source_heads(heads: &JournalHeads) -> Result<(), JournalStoreError> {
    heads.validate().map_err(supplied_decode_error)?;
    if heads.checkpoint.is_none() {
        return Err(JournalStoreError::NonCanonical);
    }
    Ok(())
}

fn source_predecessor(
    heads: &JournalHeads,
    object: &PortableJournalObject,
) -> Result<JournalHeads, JournalStoreError> {
    let previous = decode_object::<JournalHeads>(&object.bytes, JournalHeadsId(object.id))?;
    if heads.previous != Some(previous.id()) {
        return Err(JournalStoreError::NonCanonical);
    }
    previous
        .validate_successor(heads)
        .map_err(|_| JournalStoreError::NonCanonical)?;
    Ok(previous)
}

struct Sequence {
    objects: u64,
    blobs: u64,
    history: u64,
    last_object: Option<(JournalStorageClass, [u8; 32])>,
    last_blob: Option<(JournalBlobClass, Hash)>,
    keys: blake2b_simd::State,
}

impl Sequence {
    fn new() -> Self {
        Self {
            objects: 0,
            blobs: 0,
            history: 0,
            last_object: None,
            last_blob: None,
            keys: hash_state(KEYS_DOMAIN),
        }
    }

    fn object(
        &mut self,
        class: JournalStorageClass,
        id: [u8; 32],
        limits: ExternalArchiveLimits,
    ) -> Result<(), JournalStoreError> {
        if self.blobs != 0 || self.last_object.is_some_and(|last| last >= (class, id)) {
            return Err(JournalStoreError::NonCanonical);
        }
        if self.objects >= limits.max_objects as u64
            || (class == JournalStorageClass::InvocationHistoryNode
                && self.history >= limits.max_history_nodes as u64)
        {
            return Err(JournalStoreError::LimitExceeded);
        }
        self.objects += 1;
        if class == JournalStorageClass::InvocationHistoryNode {
            self.history += 1;
        }
        self.last_object = Some((class, id));
        object_key(&mut self.keys, class, &id);
        Ok(())
    }

    fn blob(
        &mut self,
        class: JournalBlobClass,
        reference: &BlobRef,
        limits: ExternalArchiveLimits,
    ) -> Result<(), JournalStoreError> {
        let key = (class, reference.hash);
        if self.last_blob.is_some_and(|last| last >= key) {
            return Err(JournalStoreError::NonCanonical);
        }
        if self.blobs >= limits.max_blobs as u64 {
            return Err(JournalStoreError::LimitExceeded);
        }
        self.blobs += 1;
        self.last_blob = Some(key);
        blob_key(&mut self.keys, class, reference);
        Ok(())
    }
}

struct ArchiveWriter<'a, W> {
    output: &'a mut W,
    limits: ExternalArchiveLimits,
    source_heads: JournalHeads,
    source_predecessor: Option<JournalHeads>,
    sequence: Sequence,
    wire_bytes: u64,
    archive: blake2b_simd::State,
    failed: bool,
}

impl<'a, W: Write> ArchiveWriter<'a, W> {
    fn new(
        output: &'a mut W,
        heads: &JournalHeads,
        limits: ExternalArchiveLimits,
    ) -> Result<Self, JournalStoreError> {
        limits.validate()?;
        validate_source_heads(heads)?;
        let bytes = heads.encode();
        if bytes.len() > class_maximum(JournalStorageClass::Heads) {
            return Err(JournalStoreError::LimitExceeded);
        }
        let mut writer = Self {
            output,
            limits,
            source_heads: heads.clone(),
            source_predecessor: None,
            sequence: Sequence::new(),
            wire_bytes: 0,
            archive: hash_state(ARCHIVE_DOMAIN),
            failed: false,
        };
        writer.write(MAGIC)?;
        writer.write(crate::service::PLATFORM_ID.as_bytes())?;
        writer.write(&(bytes.len() as u32).to_le_bytes())?;
        writer.write(&bytes)?;
        Ok(writer)
    }

    fn reserve(&mut self, bytes: u64) -> Result<(), JournalStoreError> {
        if self.failed
            || self
                .wire_bytes
                .checked_add(bytes)
                .is_none_or(|next| next > self.limits.max_wire_bytes)
        {
            self.failed = true;
            return Err(JournalStoreError::LimitExceeded);
        }
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), JournalStoreError> {
        self.reserve(bytes.len() as u64)?;
        if self.output.write_all(bytes).is_err() {
            self.failed = true;
            return Err(JournalStoreError::Unavailable);
        }
        self.archive.update(bytes);
        self.wire_bytes += bytes.len() as u64;
        Ok(())
    }

    fn object(&mut self, object: &PortableJournalObject) -> Result<(), JournalStoreError> {
        let result = (|| {
            self.reserve(38 + object.bytes.len() as u64)?;
            validate_portable_object(object)?;
            self.sequence.object(object.class, object.id, self.limits)?;
            if object.class == JournalStorageClass::Heads {
                self.source_predecessor = Some(source_predecessor(&self.source_heads, object)?);
            }
            self.write(&[OBJECT, object.class as u8])?;
            self.write(&object.id)?;
            self.write(&(object.bytes.len() as u32).to_le_bytes())?;
            self.write(&object.bytes)
        })();
        self.failed |= result.is_err();
        result
    }

    fn blob(
        &mut self,
        class: JournalBlobClass,
        reference: &BlobRef,
        bytes: &[u8],
    ) -> Result<(), JournalStoreError> {
        let result = (|| {
            self.reserve(46 + bytes.len() as u64)?;
            validate_supplied_blob(class, reference, bytes)?;
            self.sequence.blob(class, reference, self.limits)?;
            self.write(&[BLOB, class as u8])?;
            self.write(&reference.hash.0)?;
            self.write(&reference.len.to_le_bytes())?;
            self.write(&(bytes.len() as u32).to_le_bytes())?;
            self.write(bytes)
        })();
        self.failed |= result.is_err();
        result
    }

    fn finish(mut self) -> Result<ExternalArchiveReport, JournalStoreError> {
        self.reserve(FOOTER_BYTES)?;
        if self.source_heads.previous != self.source_predecessor.as_ref().map(JournalHeads::id) {
            return Err(JournalStoreError::NonCanonical);
        }
        let total = self.wire_bytes + FOOTER_BYTES;
        let keys = finish_hash(&self.sequence.keys);
        self.write(&[END])?;
        self.write(&self.sequence.objects.to_le_bytes())?;
        self.write(&self.sequence.blobs.to_le_bytes())?;
        self.write(&self.sequence.history.to_le_bytes())?;
        self.write(&total.to_le_bytes())?;
        self.write(&keys.0)?;
        let identity = finish_hash(&self.archive);
        // The identity authenticates all preceding archive bytes, not itself.
        if self.output.write_all(&identity.0).is_err() {
            return Err(JournalStoreError::Unavailable);
        }
        self.wire_bytes += 32;
        Ok(ExternalArchiveReport {
            source_heads: self.source_heads,
            source_predecessor: self.source_predecessor,
            objects: self.sequence.objects,
            blobs: self.sequence.blobs,
            history_nodes: self.sequence.history,
            wire_bytes: self.wire_bytes,
            keys,
            identity,
        })
    }
}

/// Export an already bounded, independently selected mark. The caller retains
/// its exclusive owner/borrowed availability over mark construction and this
/// call. This function does not mint authority or re-traverse cumulative
/// history. It retains only the existing ID-only mark and one payload.
pub(super) fn write_marked_external_archive<S: AgentJournalStore, W: Write>(
    store: &S,
    heads: &JournalHeads,
    mark: &GcMark,
    availability: Option<&ExternalCheckpointValidation<'_>>,
    output: &mut W,
    limits: ExternalArchiveLimits,
) -> Result<ExternalArchiveReport, JournalStoreError> {
    limits.validate()?;
    if mark.objects.len() > limits.max_objects
        || mark.blobs.len() > limits.max_blobs
        || mark
            .objects
            .iter()
            .filter(|(class, _)| *class == JournalStorageClass::InvocationHistoryNode)
            .count()
            > limits.max_history_nodes
    {
        return Err(JournalStoreError::LimitExceeded);
    }
    let (current, _) = fresh_gc_checkpoint_with_availability(store, heads.id(), availability)?;
    if current != *heads {
        return Err(JournalStoreError::Conflict);
    }
    let mut writer = ArchiveWriter::new(output, heads, limits)?;
    for (class, id) in &mark.objects {
        // File/typed stores already cap this read at the class's payload
        // maximum. The wire allowance charges the actual encoded record,
        // not its possibly much larger type ceiling.
        writer.reserve(38)?;
        let object = read_portable_object(store, *class, *id)?;
        writer.object(&object)?;
    }
    for ((class, hash), length) in &mark.blobs {
        let reference = BlobRef {
            hash: *hash,
            len: *length,
        };
        validate_blob_reference(*class, &reference)?;
        writer.reserve(46 + reference.len)?;
        let bytes = store
            .load_blob(*class, &reference)?
            .ok_or(JournalStoreError::MissingObject)?;
        writer.blob(*class, &reference, &bytes)?;
    }
    if store.heads()?.as_ref() != Some(heads) {
        return Err(JournalStoreError::Conflict);
    }
    writer.finish()
}

struct ArchiveReader<'a, R> {
    input: &'a mut R,
    limits: ExternalArchiveLimits,
    wire_bytes: u64,
    archive: blake2b_simd::State,
}

impl<R: Read> ArchiveReader<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> Result<(), JournalStoreError> {
        if self
            .wire_bytes
            .checked_add(output.len() as u64)
            .is_none_or(|next| next > self.limits.max_wire_bytes)
        {
            return Err(JournalStoreError::LimitExceeded);
        }
        self.input.read_exact(output).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                JournalStoreError::NonCanonical
            } else {
                JournalStoreError::Unavailable
            }
        })?;
        self.archive.update(output);
        self.wire_bytes += output.len() as u64;
        Ok(())
    }

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], JournalStoreError> {
        let mut bytes = [0; N];
        self.read(&mut bytes)?;
        Ok(bytes)
    }

    fn payload(&mut self, length: usize, maximum: usize) -> Result<Vec<u8>, JournalStoreError> {
        if length > maximum
            || self
                .wire_bytes
                .checked_add(length as u64)
                .is_none_or(|next| next > self.limits.max_wire_bytes)
        {
            return Err(JournalStoreError::LimitExceeded);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| JournalStoreError::LimitExceeded)?;
        bytes.resize(length, 0);
        self.read(&mut bytes)?;
        Ok(bytes)
    }
}

/// Strict streaming decode and optional immutable staging. The expected
/// source head is independently selected by the caller (e.g. authenticated
/// host QC metadata) and is checked before any callback. Successful return
/// means framing/content integrity only, never complete rooted availability.
/// A callback failure may leave safe immutable prefixes staged; it cannot
/// activate a head. Exact source Heads are captured instead of staged.
pub(crate) fn read_external_archive<R: Read>(
    input: &mut R,
    expected_source_heads: JournalHeadsId,
    limits: ExternalArchiveLimits,
    mut stage: impl FnMut(ExternalArchiveRecord<'_>) -> Result<(), JournalStoreError>,
) -> Result<ExternalArchiveReport, JournalStoreError> {
    limits.validate()?;
    let mut reader = ArchiveReader {
        input,
        limits,
        wire_bytes: 0,
        archive: hash_state(ARCHIVE_DOMAIN),
    };
    if reader.bytes::<4>()? != *MAGIC || reader.bytes::<32>()? != crate::service::PLATFORM_ID.0 {
        return Err(JournalStoreError::NonCanonical);
    }
    let length = u32::from_le_bytes(reader.bytes()?) as usize;
    let bytes = reader.payload(length, class_maximum(JournalStorageClass::Heads))?;
    let heads = JournalHeads::decode(&bytes).map_err(supplied_decode_error)?;
    if heads.encode() != bytes {
        return Err(JournalStoreError::NonCanonical);
    }
    validate_source_heads(&heads)?;
    if heads.id() != expected_source_heads {
        return Err(JournalStoreError::ScopeMismatch);
    }
    drop(bytes);
    let mut predecessor = None;
    let mut sequence = Sequence::new();
    loop {
        match reader.bytes::<1>()?[0] {
            OBJECT => {
                let class = decode_journal_storage_class(reader.bytes::<1>()?[0])
                    .map_err(supplied_decode_error)?;
                if class == JournalStorageClass::Genesis {
                    return Err(JournalStoreError::InvalidClass);
                }
                let id = reader.bytes()?;
                let length = u32::from_le_bytes(reader.bytes()?) as usize;
                sequence.object(class, id, limits)?;
                let bytes = reader.payload(length, class_maximum(class))?;
                let object = PortableJournalObject { class, id, bytes };
                validate_portable_object(&object)?;
                if class == JournalStorageClass::Heads {
                    predecessor = Some(source_predecessor(&heads, &object)?);
                } else {
                    stage(ExternalArchiveRecord::Object {
                        class,
                        id,
                        bytes: &object.bytes,
                    })?;
                }
            }
            BLOB => {
                let class = decode_journal_blob_class(reader.bytes::<1>()?[0])
                    .map_err(supplied_decode_error)?;
                let reference = BlobRef {
                    hash: Hash(reader.bytes()?),
                    len: u64::from_le_bytes(reader.bytes()?),
                };
                let length = u32::from_le_bytes(reader.bytes()?) as usize;
                validate_blob_reference(class, &reference)?;
                if reference.len != length as u64 {
                    return Err(JournalStoreError::NonCanonical);
                }
                sequence.blob(class, &reference, limits)?;
                let bytes = reader.payload(length, blob_maximum(class))?;
                validate_supplied_blob(class, &reference, &bytes)?;
                stage(ExternalArchiveRecord::Blob {
                    class,
                    reference: &reference,
                    bytes: &bytes,
                })?;
            }
            END => break,
            _ => return Err(JournalStoreError::NonCanonical),
        }
    }
    let objects = u64::from_le_bytes(reader.bytes()?);
    let blobs = u64::from_le_bytes(reader.bytes()?);
    let history = u64::from_le_bytes(reader.bytes()?);
    let wire_bytes = u64::from_le_bytes(reader.bytes()?);
    let keys = Hash(reader.bytes()?);
    let expected_identity = finish_hash(&reader.archive);
    let mut identity = [0; 32];
    // The trailing identity is excluded from the archive hash, but included
    // in the wire budget. No more than one payload survives a loop iteration.
    if reader
        .wire_bytes
        .checked_add(32)
        .is_none_or(|next| next > limits.max_wire_bytes)
    {
        return Err(JournalStoreError::LimitExceeded);
    }
    reader.input.read_exact(&mut identity).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            JournalStoreError::NonCanonical
        } else {
            JournalStoreError::Unavailable
        }
    })?;
    reader.wire_bytes += 32;
    let mut trailing = [0];
    loop {
        match reader.input.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => return Err(JournalStoreError::NonCanonical),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(JournalStoreError::Unavailable),
        }
    }
    if objects != sequence.objects
        || blobs != sequence.blobs
        || history != sequence.history
        || wire_bytes != reader.wire_bytes
        || keys != finish_hash(&sequence.keys)
        || Hash(identity) != expected_identity
        || heads.previous != predecessor.as_ref().map(JournalHeads::id)
    {
        return Err(JournalStoreError::NonCanonical);
    }
    Ok(ExternalArchiveReport {
        source_heads: heads,
        source_predecessor: predecessor,
        objects,
        blobs,
        history_nodes: history,
        wire_bytes,
        keys,
        identity: Hash(identity),
    })
}

/// Compare decoded record membership with one independently audited bounded
/// mark. Content IDs/reference lengths bind the payloads; canonical ordering
/// makes a second imported key map unnecessary. This comparison itself is
/// not an audit and creates no availability/publication capability.
pub(super) fn validate_external_archive_mark(
    report: &ExternalArchiveReport,
    mark: &GcMark,
) -> Result<(), JournalStoreError> {
    let mut keys = hash_state(KEYS_DOMAIN);
    let mut history = 0_u64;
    for (class, id) in &mark.objects {
        object_key(&mut keys, *class, id);
        history += u64::from(*class == JournalStorageClass::InvocationHistoryNode);
    }
    for ((class, hash), length) in &mark.blobs {
        blob_key(
            &mut keys,
            *class,
            &BlobRef {
                hash: *hash,
                len: *length,
            },
        );
    }
    if report.objects != mark.objects.len() as u64
        || report.blobs != mark.blobs.len() as u64
        || report.history_nodes != history
        || report.keys != finish_hash(&keys)
    {
        return Err(JournalStoreError::NonCanonical);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::journal::InvocationAcknowledgedFact;

    fn fixture() -> (JournalHeads, PortableJournalObject) {
        let common = crate::agent::shared_commit::common_snapshot_claim_for_test();
        let claim = common.ordered();
        let previous = JournalHeads::initial(
            claim.genesis(),
            claim.admission(),
            common.active_committee().members()[0].replica().node,
            claim.merge_frontier(),
            claim.runtime().clone(),
        );
        let mut heads = previous.clone();
        heads.publication_revision = 1;
        heads.previous = Some(previous.id());
        heads.checkpoint = Some(CheckpointId([0x57; 32]));
        let object = PortableJournalObject {
            class: JournalStorageClass::Heads,
            id: previous.id().0,
            bytes: previous.encode(),
        };
        (heads, object)
    }

    fn limits() -> ExternalArchiveLimits {
        ExternalArchiveLimits {
            max_objects: 100_000,
            max_blobs: 100_000,
            max_history_nodes: 100_000,
            max_wire_bytes: 128 * 1024 * 1024,
        }
    }

    fn decode<R: Read>(
        input: &mut R,
        limits: ExternalArchiveLimits,
        stage: impl FnMut(ExternalArchiveRecord<'_>) -> Result<(), JournalStoreError>,
    ) -> Result<ExternalArchiveReport, JournalStoreError> {
        read_external_archive(input, fixture().0.id(), limits, stage)
    }

    fn archive() -> Vec<u8> {
        let (heads, previous) = fixture();
        let mut bytes = Vec::new();
        let mut writer = ArchiveWriter::new(&mut bytes, &heads, limits()).unwrap();
        writer.object(&previous).unwrap();
        let payload = b"archive fixture";
        let reference = BlobRef::of_bytes(payload);
        writer
            .blob(JournalBlobClass::CatalogArtifact, &reference, payload)
            .unwrap();
        writer.finish().unwrap();
        bytes
    }

    struct Short<T>(T);
    impl<T: Read> Read for Short<T> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let length = output.len().min(3);
            self.0.read(&mut output[..length])
        }
    }
    impl<T: Write> Write for Short<T> {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            self.0.write(&input[..input.len().min(3)])
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }

    #[test]
    fn short_io_roundtrip_retains_foreign_heads_as_metadata_only() {
        let (heads, previous) = fixture();
        let mut bytes = Vec::new();
        let mut output = Short(&mut bytes);
        let mut writer = ArchiveWriter::new(&mut output, &heads, limits()).unwrap();
        writer.object(&previous).unwrap();
        let reference = BlobRef::of_bytes(b"payload");
        writer
            .blob(JournalBlobClass::CatalogArtifact, &reference, b"payload")
            .unwrap();
        let written = writer.finish().unwrap();
        let mut records = 0;
        let decoded = decode(&mut Short(bytes.as_slice()), limits(), |record| {
            assert!(matches!(record, ExternalArchiveRecord::Blob { .. }));
            records += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(records, 1);
        assert_eq!(decoded.source_heads, heads);
        assert_eq!(decoded.source_predecessor.unwrap().id().0, previous.id);
        assert_eq!(decoded.identity, written.identity);
        assert_eq!(decoded.keys, written.keys);
        assert_eq!(decoded.wire_bytes, bytes.len() as u64);
    }

    #[test]
    fn source_predecessor_rejects_changed_runtime_scope_before_staging() {
        let (heads, previous) = fixture();
        let mut wrong_space = heads.clone();
        wrong_space.runtime.space.0[0] ^= 1;
        let mut wrong_agent = heads.clone();
        wrong_agent.runtime.agent.0[0] ^= 1;
        for wrong in [wrong_space, wrong_agent] {
            wrong.validate().unwrap();
            let mut output = Vec::new();
            let mut writer = ArchiveWriter::new(&mut output, &wrong, limits()).unwrap();
            assert_eq!(
                writer.object(&previous).unwrap_err(),
                JournalStoreError::NonCanonical
            );
            assert!(writer.finish().is_err());

            let mut bytes = archive();
            bytes[40..40 + heads.encode().len()].copy_from_slice(&wrong.encode());
            let mut staged = 0;
            assert_eq!(
                read_external_archive(&mut bytes.as_slice(), wrong.id(), limits(), |_| {
                    staged += 1;
                    Ok(())
                })
                .unwrap_err(),
                JournalStoreError::NonCanonical
            );
            assert_eq!(staged, 0);
        }
    }

    #[test]
    fn truncation_trailing_bytes_and_corrupt_identity_fail() {
        let bytes = archive();
        for end in [0, 3, 39, bytes.len() / 2, bytes.len() - 1] {
            assert!(decode(&mut &bytes[..end], limits(), |_| Ok(())).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&mut trailing.as_slice(), limits(), |_| Ok(())).is_err());
        let mut corrupt = bytes;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(decode(&mut corrupt.as_slice(), limits(), |_| Ok(())).is_err());
    }

    #[test]
    fn corrupt_payload_never_reaches_staging() {
        let (heads, previous) = fixture();
        let mut bytes = archive();
        let payload = 40 + heads.encode().len() + 38 + previous.bytes.len() + 46;
        bytes[payload] ^= 1;
        let mut staged = 0;
        assert!(
            decode(&mut bytes.as_slice(), limits(), |_| {
                staged += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(staged, 0);
    }

    #[test]
    fn wire_budget_and_oversized_header_reject_before_payload_read() {
        let bytes = archive();
        let mut exact = limits();
        exact.max_wire_bytes = bytes.len() as u64;
        decode(&mut bytes.as_slice(), exact, |_| Ok(())).unwrap();
        exact.max_wire_bytes -= 1;
        assert_eq!(
            decode(&mut bytes.as_slice(), exact, |_| Ok(())).unwrap_err(),
            JournalStoreError::LimitExceeded
        );
        let mut prefix = Vec::new();
        prefix.extend_from_slice(MAGIC);
        prefix.extend_from_slice(crate::service::PLATFORM_ID.as_bytes());
        prefix.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode(&mut prefix.as_slice(), limits(), |_| Ok(())).unwrap_err(),
            JournalStoreError::LimitExceeded
        );
    }

    #[test]
    fn reader_rejects_duplicate_order_and_oversized_frames_before_staging() {
        let (heads, previous) = fixture();
        let bytes = archive();
        let first = 40 + heads.encode().len();
        let end = first + 38 + previous.bytes.len();
        let mut duplicate = bytes[..end].to_vec();
        duplicate.extend_from_slice(&bytes[first..end]);
        duplicate.extend_from_slice(&bytes[end..]);
        let mut staged = 0;
        assert_eq!(
            decode(&mut duplicate.as_slice(), limits(), |_| {
                staged += 1;
                Ok(())
            })
            .unwrap_err(),
            JournalStoreError::NonCanonical,
        );
        assert_eq!(
            staged, 0,
            "Heads never reach staging, including duplicate input"
        );
        let mut oversized = bytes;
        oversized[first + 34..first + 38].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut input = std::io::Cursor::new(oversized);
        assert_eq!(
            decode(&mut input, limits(), |_| Ok(())).unwrap_err(),
            JournalStoreError::LimitExceeded
        );
        assert_eq!(input.position() as usize, first + 38);

        let mut payloads = [
            (BlobRef::of_bytes(b"a"), b"a".as_slice()),
            (BlobRef::of_bytes(b"b"), b"b".as_slice()),
        ];
        payloads.sort_by_key(|(reference, _)| reference.hash);
        let mut bytes = Vec::new();
        let mut writer = ArchiveWriter::new(&mut bytes, &heads, limits()).unwrap();
        writer.object(&previous).unwrap();
        for (reference, payload) in &payloads {
            writer
                .blob(JournalBlobClass::CatalogArtifact, reference, payload)
                .unwrap();
        }
        writer.finish().unwrap();
        let first_blob = end;
        let mut reversed = bytes[..first_blob].to_vec();
        reversed.extend_from_slice(&bytes[first_blob + 47..first_blob + 94]);
        reversed.extend_from_slice(&bytes[first_blob..first_blob + 47]);
        reversed.extend_from_slice(&bytes[first_blob + 94..]);
        assert_eq!(
            decode(&mut reversed.as_slice(), limits(), |_| Ok(())).unwrap_err(),
            JournalStoreError::NonCanonical
        );
    }

    #[test]
    fn selected_head_and_callback_failures_cannot_produce_a_report() {
        let bytes = archive();
        let mut staged = 0;
        assert_eq!(
            read_external_archive(
                &mut bytes.as_slice(),
                JournalHeadsId([0x99; 32]),
                limits(),
                |_| {
                    staged += 1;
                    Ok(())
                }
            )
            .unwrap_err(),
            JournalStoreError::ScopeMismatch,
        );
        assert_eq!(staged, 0);
        assert_eq!(
            decode(&mut bytes.as_slice(), limits(), |_| Err(
                JournalStoreError::Unavailable
            ))
            .unwrap_err(),
            JournalStoreError::Unavailable
        );
        let mut invalid = limits();
        invalid.max_objects = 0;
        assert_eq!(
            decode(&mut bytes.as_slice(), invalid, |_| Ok(())).unwrap_err(),
            JournalStoreError::LimitExceeded
        );
    }

    struct FailingWriter {
        remaining: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            let count = self.remaining.min(bytes.len());
            self.remaining -= count;
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn failed_write_cannot_finish_or_claim_a_complete_archive() {
        let (heads, previous) = fixture();
        let mut output = FailingWriter {
            remaining: 40 + heads.encode().len() + 12,
        };
        let mut writer = ArchiveWriter::new(&mut output, &heads, limits()).unwrap();
        assert_eq!(
            writer.object(&previous).unwrap_err(),
            JournalStoreError::Unavailable
        );
        assert!(writer.finish().is_err());
    }

    #[test]
    fn duplicate_and_out_of_order_records_poison_writer() {
        let (heads, previous) = fixture();
        let mut bytes = Vec::new();
        let mut writer = ArchiveWriter::new(&mut bytes, &heads, limits()).unwrap();
        writer.object(&previous).unwrap();
        assert_eq!(
            writer.object(&previous).unwrap_err(),
            JournalStoreError::NonCanonical
        );
        assert!(writer.finish().is_err());
        let mut payloads = [
            (BlobRef::of_bytes(b"a"), b"a".as_slice()),
            (BlobRef::of_bytes(b"b"), b"b".as_slice()),
        ];
        payloads.sort_by_key(|(reference, _)| reference.hash);
        let mut writer = ArchiveWriter::new(&mut bytes, &heads, limits()).unwrap();
        writer.object(&previous).unwrap();
        writer
            .blob(
                JournalBlobClass::CatalogArtifact,
                &payloads[1].0,
                payloads[1].1,
            )
            .unwrap();
        assert_eq!(
            writer
                .blob(
                    JournalBlobClass::CatalogArtifact,
                    &payloads[0].0,
                    payloads[0].1
                )
                .unwrap_err(),
            JournalStoreError::NonCanonical
        );
        assert!(writer.finish().is_err());
    }

    #[test]
    fn counts_and_membership_are_independent_of_ajb1_ceilings() {
        // Codec capacity only: synthetic leaves are not a rooted customer
        // dataset or evidence for public activation/performance qualification.
        let count = MAX_PORTABLE_JOURNAL_BLOBS + 1;
        let (heads, previous) = fixture();
        let mut nodes = BTreeMap::new();
        let mut blobs = BTreeMap::new();
        for nonce in 0..count as u32 {
            let mut identity = [0x81; 32];
            identity[..4].copy_from_slice(&nonce.to_le_bytes());
            let key = crate::agent_sdk::proof::TransitionProofKey {
                invocation: crate::agent_sdk::InvocationId(identity),
                execution: crate::agent_sdk::Hash([0x82; 32]),
            };
            let fact =
                InvocationAcknowledgedFact::for_transition_proof_retirement(heads.genesis, key)
                    .unwrap();
            let node = InvocationHistoryNode::Leaf(fact);
            nodes.insert(node.id().0, nonce);
            blobs.insert(BlobRef::of_bytes(&nonce.to_le_bytes()).hash, nonce);
        }
        let mut bytes = Vec::new();
        let mut writer = ArchiveWriter::new(&mut bytes, &heads, limits()).unwrap();
        writer.object(&previous).unwrap();
        let mut mark = GcMark::new(GcLimits {
            max_index_nodes: count,
            max_marked_objects: count + 1,
            max_marked_blobs: count,
            max_scanned_files: 1,
            max_scanned_bytes: 1,
            max_unlinks_per_run: 1,
        });
        mark.object::<JournalHeads>(JournalHeadsId(previous.id))
            .unwrap();
        for (id, nonce) in nodes {
            let mut identity = [0x81; 32];
            identity[..4].copy_from_slice(&nonce.to_le_bytes());
            let key = crate::agent_sdk::proof::TransitionProofKey {
                invocation: crate::agent_sdk::InvocationId(identity),
                execution: crate::agent_sdk::Hash([0x82; 32]),
            };
            let fact =
                InvocationAcknowledgedFact::for_transition_proof_retirement(heads.genesis, key)
                    .unwrap();
            let node = InvocationHistoryNode::Leaf(fact);
            writer
                .object(&PortableJournalObject {
                    class: JournalStorageClass::InvocationHistoryNode,
                    id,
                    bytes: node.encode(),
                })
                .unwrap();
            mark.object::<InvocationHistoryNode>(InvocationHistoryNodeId(id))
                .unwrap();
        }
        for (hash, nonce) in blobs {
            let payload = nonce.to_le_bytes();
            let reference = BlobRef {
                hash,
                len: payload.len() as u64,
            };
            writer
                .blob(JournalBlobClass::CatalogArtifact, &reference, &payload)
                .unwrap();
            mark.blob(JournalBlobClass::CatalogArtifact, &reference)
                .unwrap();
        }
        let written = writer.finish().unwrap();
        let decoded = decode(&mut bytes.as_slice(), limits(), |_| Ok(())).unwrap();
        assert_eq!(decoded.objects, count as u64 + 1);
        assert_eq!(decoded.blobs, count as u64);
        assert_eq!(decoded.history_nodes, count as u64);
        assert_eq!(decoded.identity, written.identity);
        validate_external_archive_mark(&decoded, &mark).unwrap();
        mark.blobs.pop_first();
        assert_eq!(
            validate_external_archive_mark(&decoded, &mark),
            Err(JournalStoreError::NonCanonical)
        );
        let mut limited = limits();
        limited.max_history_nodes = count - 1;
        assert_eq!(
            decode(&mut bytes.as_slice(), limited, |_| Ok(())).unwrap_err(),
            JournalStoreError::LimitExceeded
        );
        limited = limits();
        limited.max_blobs = count - 1;
        assert_eq!(
            decode(&mut bytes.as_slice(), limited, |_| Ok(())).unwrap_err(),
            JournalStoreError::LimitExceeded
        );
        limited = limits();
        limited.max_objects = count;
        limited.max_history_nodes = count;
        assert_eq!(
            decode(&mut bytes.as_slice(), limited, |_| Ok(())).unwrap_err(),
            JournalStoreError::LimitExceeded
        );
    }
}
