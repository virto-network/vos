//! Clean runtime-owned lane image: inline actor fields plus independent rows.
//!
//! Rows must not be sent to the inner guest as part of its inline snapshot.
//! This codec is a prerequisite for clean storage execution, not an installed
//! storage backend. Runtime integration must authenticate the actor/generation,
//! signed field prefixes and method lane before exposing or mutating rows.

use crate::agent_sdk::RUNTIME_ABI_ID;
use crate::agent_sdk::{MethodMode, StateLane, schema::ParsedSchema};
use crate::service::wire::{DecodeError, Decoder, Encoder};
use alloc::{collections::BTreeMap, vec::Vec};

const MAGIC: &[u8; 4] = b"ALI1";
const HEADER_BYTES: usize = 4 + 32 + 4 + 4;
const MAX_IMAGE_BYTES: usize = super::execution::MAX_RUNTIME_STATE_BYTES;
const MAX_INLINE_BYTES: usize = super::execution::MAX_EXECUTION_STATE_BYTES;
const MAX_ROW_BYTES: usize = crate::actors::storage::MAX_VALUE_BYTES;
// A key is a bounded byte string, not a truncated/prefix-matched identity.
pub(crate) const MAX_KEY_BYTES: usize = MAX_ROW_BYTES;
const MAX_ROWS: usize = super::standard::MAX_LANE_STATE_ENTRIES;
pub(crate) const MAX_ROW_DELTA_BYTES: usize = MAX_IMAGE_BYTES;

pub(crate) fn encode_row_delta(
    changes: &[(Vec<u8>, Option<Vec<u8>>)],
) -> Result<Vec<u8>, DecodeError> {
    if changes.len() > MAX_ROWS {
        return Err(DecodeError::LimitExceeded);
    }
    let mut size = 40usize;
    let mut previous: Option<&[u8]> = None;
    for (key, value) in changes {
        if key.is_empty()
            || key.len() > MAX_KEY_BYTES
            || value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_ROW_BYTES)
        {
            return Err(DecodeError::LimitExceeded);
        }
        if previous.is_some_and(|previous| previous >= key.as_slice()) {
            return Err(DecodeError::NonCanonical);
        }
        previous = Some(key);
        size = size
            .checked_add(5 + key.len())
            .and_then(|size| size.checked_add(value.as_ref().map_or(0, |value| 4 + value.len())))
            .filter(|size| *size <= MAX_ROW_DELTA_BYTES)
            .ok_or(DecodeError::LimitExceeded)?;
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(b"ARD1");
    bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
    let mut encoder = Encoder(&mut bytes);
    encoder.u32(u32::try_from(changes.len()).map_err(|_| DecodeError::LimitExceeded)?);
    for (key, value) in changes {
        encoder.bytes(key);
        encoder.option(value, |encoder, value| encoder.bytes(value));
    }
    debug_assert_eq!(bytes.len(), size);
    Ok(bytes)
}

pub(crate) fn decode_row_delta(
    bytes: &[u8],
) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>, DecodeError> {
    if bytes.len() > MAX_ROW_DELTA_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(4)? != b"ARD1" {
        return Err(DecodeError::InvalidTag);
    }
    if decoder.fixed()? != RUNTIME_ABI_ID.0 {
        return Err(DecodeError::InvalidPlatform);
    }
    let count = decoder.u32()? as usize;
    if count > MAX_ROWS || count > bytes.len().saturating_sub(40) / 6 {
        return Err(DecodeError::LimitExceeded);
    }
    let mut changes: Vec<(Vec<u8>, Option<Vec<u8>>)> = Vec::with_capacity(count);
    for _ in 0..count {
        let key = decoder.bytes_ref()?;
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        if changes
            .last()
            .is_some_and(|(previous, _)| previous.as_slice() >= key)
        {
            return Err(DecodeError::NonCanonical);
        }
        let value = decoder.option(|decoder| {
            let bytes = decoder.bytes_ref()?;
            if bytes.len() > MAX_ROW_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            Ok(bytes.to_vec())
        })?;
        changes.push((key.to_vec(), value));
    }
    if !decoder.exhausted() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(changes)
}

/// Runtime-owned row view. The guest supplies a key, never an actor or lane.
/// Each image must come from the actor/generation used to resolve `access`;
/// this type checks namespace ownership, not the enclosing runtime identity.
pub(crate) struct ActorStorageReader<'a> {
    access: ActorStorageAccess,
    images: [Option<&'a BTreeMap<Vec<u8>, Vec<u8>>>; 3],
}

impl<'a> ActorStorageReader<'a> {
    pub(crate) fn new(
        access: &ActorStorageAccess,
        linear: Option<&'a ActorLaneImage>,
        merge: Option<&'a ActorLaneImage>,
        local: Option<&'a ActorLaneImage>,
    ) -> Result<Self, StorageAccessError> {
        Self::from_rows(
            access.clone(),
            [
                linear.map(|image| &image.rows),
                merge.map(|image| &image.rows),
                local.map(|image| &image.rows),
            ],
        )
    }

    /// Borrow already-materialized rows without copying them into another
    /// image or the inner guest heap. Only the small namespace scope is owned.
    pub(crate) fn from_rows(
        access: ActorStorageAccess,
        images: [Option<&'a BTreeMap<Vec<u8>, Vec<u8>>>; 3],
    ) -> Result<Self, StorageAccessError> {
        for (lane, rows) in [StateLane::Linear, StateLane::Merge, StateLane::Local]
            .into_iter()
            .zip(images)
        {
            if let Some(rows) = rows {
                access.validate_rows(lane, rows)?;
            }
        }
        Ok(Self { access, images })
    }

    pub(crate) fn mode(&self) -> MethodMode {
        self.access.mode
    }

    pub(crate) fn validate_delta(
        &self,
        changes: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<(), StorageAccessError> {
        for (key, _) in changes {
            if !self.access.mode.can_write(self.access.owner_lane(key)?) {
                return Err(StorageAccessError::Forbidden);
            }
        }
        Ok(())
    }

    pub(crate) fn read(&self, key: &[u8]) -> Result<Option<&'a [u8]>, StorageAccessError> {
        let lane = self.access.owner_lane(key)?;
        // Check access even when the hidden lane has no image: absence is
        // not permission and must not make an illegal read appear valid.
        if !self.access.mode.can_read(lane) {
            return Err(StorageAccessError::Forbidden);
        }
        let index = match lane {
            StateLane::Linear => 0,
            StateLane::Merge => 1,
            StateLane::Local => 2,
        };
        match self.images[index] {
            Some(rows) => Ok(rows.get(key).map(Vec::as_slice)),
            None => Ok(None),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StorageAccessError {
    InvalidSchema,
    InvalidMethod,
    InvalidKey,
    UndeclaredNamespace,
    WrongLane,
    Forbidden,
    Image(DecodeError),
}

/// Invocation-local access derived from the installed, authenticated schema.
/// Constructing this value does NOT authenticate a package or invocation: the
/// runtime must first check the exact schema commitment and actor generation.
/// The guest never chooses this scope or the physical lane passed to row IO.
#[derive(Clone)]
pub(crate) struct ActorStorageAccess {
    namespaces: Vec<(Vec<u8>, StateLane)>,
    mode: MethodMode,
}

impl ActorStorageAccess {
    pub(crate) fn new(
        schema: &ParsedSchema,
        method: &str,
        mode: MethodMode,
    ) -> Result<Self, StorageAccessError> {
        schema
            .validate()
            .map_err(|_| StorageAccessError::InvalidSchema)?;
        if !schema
            .methods
            .iter()
            .any(|entry| entry.name == method && entry.mode == mode)
        {
            return Err(StorageAccessError::InvalidMethod);
        }
        let mut namespaces = schema
            .storage_fields()
            .map(|field| (field.prefix.clone(), field.lane))
            .collect::<Vec<_>>();
        namespaces.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        Ok(Self { namespaces, mode })
    }

    fn owner_lane(&self, key: &[u8]) -> Result<StateLane, StorageAccessError> {
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(StorageAccessError::InvalidKey);
        }
        // Schema validation rejects overlapping prefixes. The predecessor is
        // therefore the only possible owning namespace; no row scan is needed.
        let index = self
            .namespaces
            .partition_point(|(prefix, _)| prefix.as_slice() <= key);
        index
            .checked_sub(1)
            .and_then(|index| self.namespaces.get(index))
            .filter(|(prefix, _)| key.starts_with(prefix))
            .map(|(_, lane)| *lane)
            .ok_or(StorageAccessError::UndeclaredNamespace)
    }

    /// Validate persisted namespace ownership, including hidden lanes. This is
    /// an image-admission check, not a grant to read those lanes in this method.
    pub(crate) fn validate_image(
        &self,
        lane: StateLane,
        image: &ActorLaneImage,
    ) -> Result<(), StorageAccessError> {
        self.validate_rows(lane, &image.rows)
    }

    fn validate_rows(
        &self,
        lane: StateLane,
        rows: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Result<(), StorageAccessError> {
        if rows.len() > MAX_ROWS {
            return Err(StorageAccessError::Image(DecodeError::LimitExceeded));
        }
        for (key, value) in rows {
            if value.len() > MAX_ROW_BYTES {
                return Err(StorageAccessError::Image(DecodeError::LimitExceeded));
            }
            if self.owner_lane(key)? != lane {
                return Err(StorageAccessError::WrongLane);
            }
        }
        Ok(())
    }

    pub(crate) fn read<'a>(
        &self,
        lane: StateLane,
        image: &'a ActorLaneImage,
        key: &[u8],
    ) -> Result<Option<&'a [u8]>, StorageAccessError> {
        if self.owner_lane(key)? != lane {
            return Err(StorageAccessError::WrongLane);
        }
        if !self.mode.can_read(lane) {
            return Err(StorageAccessError::Forbidden);
        }
        Ok(image.row(key))
    }

    pub(crate) fn write(
        &self,
        lane: StateLane,
        image: &mut ActorLaneImage,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Result<(), StorageAccessError> {
        if self.owner_lane(&key)? != lane {
            return Err(StorageAccessError::WrongLane);
        }
        if !self.mode.can_write(lane) {
            return Err(StorageAccessError::Forbidden);
        }
        image
            .write_row(key, value)
            .map_err(StorageAccessError::Image)
    }

    /// Commit one canonical row delta and inline snapshot to the owned lane.
    /// All checks precede mutation, including the *final* image size/count.
    /// Deletes/replacements release their old storage before new rows enter;
    /// a full image can therefore exchange rows without transient overfill or
    /// cloning the whole image. The enclosing runtime must still atomically
    /// commit this image with its result/continuation and outer state budget.
    pub(crate) fn apply_batch(
        &self,
        lane: StateLane,
        image: &mut ActorLaneImage,
        inline: Vec<u8>,
        changes: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> Result<(), StorageAccessError> {
        if !self.mode.can_write(lane) {
            return Err(StorageAccessError::Forbidden);
        }
        self.validate_image(lane, image)?;
        let limit = || StorageAccessError::Image(DecodeError::LimitExceeded);
        let size = image
            .encoded_len()
            .ok_or(StorageAccessError::Image(DecodeError::NonCanonical))?;
        if inline.len() > MAX_INLINE_BYTES || changes.len() > MAX_ROWS {
            return Err(limit());
        }
        let mut removed_bytes = image.inline.len();
        let mut added_bytes = inline.len();
        let mut removed_rows = 0usize;
        let mut added_rows = 0usize;
        let mut delta_bytes = inline.len();
        let mut previous: Option<&[u8]> = None;
        for (key, value) in &changes {
            if self.owner_lane(key)? != lane {
                return Err(StorageAccessError::WrongLane);
            }
            if previous.is_some_and(|previous| previous >= key.as_slice()) {
                return Err(StorageAccessError::Image(DecodeError::NonCanonical));
            }
            previous = Some(key);
            // Bound the input as well as the final state. Repeated deletes
            // and replacements cannot hide oversized transient input.
            delta_bytes = delta_bytes
                .checked_add(9)
                .and_then(|size| size.checked_add(key.len()))
                .and_then(|size| size.checked_add(value.as_ref().map_or(0, Vec::len)))
                .filter(|size| *size <= MAX_IMAGE_BYTES)
                .ok_or_else(limit)?;
            if let Some(old) = image.rows.get(key) {
                removed_bytes = removed_bytes
                    .checked_add(8 + key.len() + old.len())
                    .ok_or_else(limit)?;
                removed_rows += 1;
            }
            if let Some(value) = value {
                if value.len() > MAX_ROW_BYTES {
                    return Err(limit());
                }
                added_bytes = added_bytes
                    .checked_add(8 + key.len() + value.len())
                    .ok_or_else(limit)?;
                added_rows += 1;
            }
        }
        size.checked_sub(removed_bytes)
            .and_then(|size| size.checked_add(added_bytes))
            .filter(|size| *size <= MAX_IMAGE_BYTES)
            .ok_or_else(limit)?;
        image
            .rows
            .len()
            .checked_sub(removed_rows)
            .and_then(|count| count.checked_add(added_rows))
            .filter(|count| *count <= MAX_ROWS)
            .ok_or_else(limit)?;

        // No fallible validation below this point. Remove all old touched
        // rows first: canonical key order may put additions before deletions.
        for (key, _) in &changes {
            image.rows.remove(key);
        }
        image.inline = inline;
        for (key, value) in changes {
            if let Some(value) = value {
                image.rows.insert(key, value);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ActorLaneImage {
    inline: Vec<u8>,
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl ActorLaneImage {
    /// Internal materialization; callers must validate before admission/use.
    pub(crate) fn from_parts(inline: Vec<u8>, rows: BTreeMap<Vec<u8>, Vec<u8>>) -> Self {
        Self { inline, rows }
    }

    pub(crate) fn inline(&self) -> &[u8] {
        &self.inline
    }

    /// Raw lookup is for the runtime only, after signed namespace/lane checks.
    fn row(&self, key: &[u8]) -> Option<&[u8]> {
        self.rows.get(key).map(Vec::as_slice)
    }

    fn encoded_len(&self) -> Option<usize> {
        Self::encoded_parts_len(&self.inline, &self.rows)
    }

    pub(crate) fn encoded_parts_len(
        inline: &[u8],
        rows: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) -> Option<usize> {
        if inline.len() > MAX_INLINE_BYTES || rows.len() > MAX_ROWS {
            return None;
        }
        rows.iter()
            .try_fold(
                HEADER_BYTES.checked_add(inline.len())?,
                |size, (key, value)| {
                    if key.is_empty() || key.len() > MAX_KEY_BYTES || value.len() > MAX_ROW_BYTES {
                        return None;
                    }
                    size.checked_add(8)?
                        .checked_add(key.len())?
                        .checked_add(value.len())
                },
            )
            .filter(|size| *size <= MAX_IMAGE_BYTES)
    }

    pub(crate) fn replace_inline(&mut self, inline: Vec<u8>) -> Result<(), DecodeError> {
        let size = self.encoded_len().ok_or(DecodeError::NonCanonical)?;
        if inline.len() > MAX_INLINE_BYTES
            || size
                .checked_sub(self.inline.len())
                .and_then(|size| size.checked_add(inline.len()))
                .is_none_or(|size| size > MAX_IMAGE_BYTES)
        {
            return Err(DecodeError::LimitExceeded);
        }
        self.inline = inline;
        Ok(())
    }

    /// Apply one row change atomically. Empty values and absent rows differ.
    /// The caller must first verify the signed field prefix and write lane.
    fn write_row(&mut self, key: Vec<u8>, value: Option<Vec<u8>>) -> Result<(), DecodeError> {
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let Some(value) = value else {
            self.rows.remove(&key);
            return Ok(());
        };
        if value.len() > MAX_ROW_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let size = self.encoded_len().ok_or(DecodeError::NonCanonical)?;
        let old = self.rows.get(&key);
        if old.is_none() && self.rows.len() == MAX_ROWS {
            return Err(DecodeError::LimitExceeded);
        }
        let removed = old.map_or(0, |old| 8 + key.len() + old.len());
        let next = size
            .checked_sub(removed)
            .and_then(|size| size.checked_add(8 + key.len() + value.len()));
        if next.is_none_or(|size| size > MAX_IMAGE_BYTES) {
            return Err(DecodeError::LimitExceeded);
        }
        self.rows.insert(key, value);
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, DecodeError> {
        let size = self.encoded_len().ok_or(DecodeError::LimitExceeded)?;
        let bytes = Self::encode_parts(&self.inline, &self.rows);
        debug_assert_eq!(bytes.len(), size);
        Ok(bytes)
    }

    /// Structural encoder used by the runtime's infallible snapshot encoder.
    /// Admission must check encoded_parts_len; decoding always enforces bounds.
    pub(crate) fn encode_parts(inline: &[u8], rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<u8> {
        let mut bytes = Vec::new();
        Self::append_parts(&mut bytes, inline, rows);
        bytes
    }

    /// Append directly to an enclosing lane frame; do not materialize a
    /// second multi-megabyte image merely to copy it into that frame.
    pub(crate) fn append_parts(
        bytes: &mut Vec<u8>,
        inline: &[u8],
        rows: &BTreeMap<Vec<u8>, Vec<u8>>,
    ) {
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        let mut encoder = Encoder(bytes);
        encoder.bytes(inline);
        encoder.u32(rows.len() as u32);
        for (key, value) in rows {
            encoder.bytes(key);
            encoder.bytes(value);
        }
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, BTreeMap<Vec<u8>, Vec<u8>>) {
        (self.inline, self.rows)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_IMAGE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(4)? != MAGIC {
            return Err(DecodeError::InvalidTag);
        }
        if decoder.fixed()? != RUNTIME_ABI_ID.0 {
            return Err(DecodeError::InvalidPlatform);
        }
        let inline = decoder.bytes_ref()?;
        if inline.len() > MAX_INLINE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let count = decoder.u32()? as usize;
        // Each row needs two length prefixes and at least one key byte.
        if count > MAX_ROWS || count > bytes.len().saturating_sub(HEADER_BYTES + inline.len()) / 9 {
            return Err(DecodeError::LimitExceeded);
        }
        let mut rows = BTreeMap::new();
        for _ in 0..count {
            let key = decoder.bytes_ref()?;
            let value = decoder.bytes_ref()?;
            if key.is_empty() || key.len() > MAX_KEY_BYTES || value.len() > MAX_ROW_BYTES {
                return Err(DecodeError::LimitExceeded);
            }
            if rows
                .last_key_value()
                .is_some_and(|(previous, _): (&Vec<u8>, &Vec<u8>)| previous.as_slice() >= key)
            {
                return Err(DecodeError::NonCanonical);
            }
            rows.insert(key.to_vec(), value.to_vec());
        }
        if !decoder.exhausted() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(Self {
            inline: inline.to_vec(),
            rows,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn schema() -> ParsedSchema {
        use crate::agent_sdk::schema::{
            ConstructorContract, ParsedField, ParsedMethod, ParsedStorageField,
        };
        let fields = [StateLane::Linear, StateLane::Merge, StateLane::Local]
            .into_iter()
            .enumerate()
            .map(|(index, lane)| {
                ParsedField::Storage(ParsedStorageField {
                    source_index: index as u16,
                    name: alloc::format!("rows_{index}"),
                    type_identity: "test::StorageMap<u32,u64>".into(),
                    prefix: alloc::format!("s/{index}/").into_bytes(),
                    lane,
                    committed: false,
                    leaf_domain: None,
                    node_domain: None,
                })
            })
            .collect();
        let methods = [
            MethodMode::Query,
            MethodMode::LinearizableQuery,
            MethodMode::LocalQuery,
            MethodMode::Linear,
            MethodMode::Merge,
            MethodMode::Local,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, mode)| ParsedMethod {
            source_index: index as u16,
            name: alloc::format!("method_{index}"),
            mode,
            explicit: true,
        })
        .collect();
        ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields,
            methods,
        }
    }

    #[test]
    fn row_delta_wire_is_bounded_canonical_and_distinguishes_deletes() {
        let changes = vec![
            (b"a".to_vec(), None),
            (b"b".to_vec(), Some(Vec::new())),
            (b"c".to_vec(), Some(vec![7; MAX_ROW_BYTES])),
        ];
        let bytes = encode_row_delta(&changes).unwrap();
        assert_eq!(decode_row_delta(&bytes).unwrap(), changes);
        let mut invalid = bytes.clone();
        invalid.push(0);
        assert_eq!(decode_row_delta(&invalid), Err(DecodeError::TrailingBytes));
        for offset in [0, 4, 36] {
            let mut invalid = bytes.clone();
            invalid[offset] ^= 0xff;
            assert!(decode_row_delta(&invalid).is_err());
        }
        for changes in [
            vec![(vec![], None)],
            vec![(b"a".to_vec(), Some(vec![0; MAX_ROW_BYTES + 1]))],
            vec![(b"a".to_vec(), None), (b"a".to_vec(), Some(Vec::new()))],
            vec![(b"b".to_vec(), None), (b"a".to_vec(), None)],
        ] {
            assert!(encode_row_delta(&changes).is_err());
        }
        // Corrupt a valid distinct-key stream after encoding; the decoder
        // itself, not just the producer, must reject duplicate keys.
        let mut duplicate =
            encode_row_delta(&[(b"a".to_vec(), None), (b"b".to_vec(), None)]).unwrap();
        duplicate[40 + 6 + 4] = b'a';
        assert_eq!(decode_row_delta(&duplicate), Err(DecodeError::NonCanonical));
    }

    #[test]
    fn batch_updates_validate_every_change_before_mutating_inline_or_rows() {
        let schema = schema();
        let access = ActorStorageAccess::new(&schema, "method_3", MethodMode::Linear).unwrap();
        let mut image = ActorLaneImage::default();
        access
            .apply_batch(
                StateLane::Linear,
                &mut image,
                vec![1],
                vec![
                    (b"s/0/a".to_vec(), Some(vec![2])),
                    (b"s/0/b".to_vec(), Some(Vec::new())),
                ],
            )
            .unwrap();
        let before = image.clone();
        for changes in [
            vec![
                (b"s/0/a".to_vec(), Some(vec![9])),
                (b"undeclared".to_vec(), None),
            ],
            vec![
                (b"s/0/a".to_vec(), None),
                (b"s/1/hidden".to_vec(), Some(vec![9])),
            ],
            vec![
                (b"s/0/a".to_vec(), None),
                (b"s/0/a".to_vec(), Some(vec![9])),
            ],
            vec![
                (b"s/0/b".to_vec(), None),
                (b"s/0/a".to_vec(), Some(vec![9])),
            ],
            vec![
                (b"s/0/a".to_vec(), None),
                (b"s/0/b".to_vec(), Some(vec![0; MAX_ROW_BYTES + 1])),
            ],
        ] {
            assert!(
                access
                    .apply_batch(StateLane::Linear, &mut image, vec![3], changes)
                    .is_err()
            );
            assert_eq!(image, before);
        }
        assert!(
            access
                .apply_batch(
                    StateLane::Linear,
                    &mut image,
                    vec![0; MAX_INLINE_BYTES + 1],
                    Vec::new()
                )
                .is_err()
        );
        assert_eq!(image, before);
        let query = ActorStorageAccess::new(&schema, "method_0", MethodMode::Query).unwrap();
        assert_eq!(
            query.apply_batch(StateLane::Linear, &mut image, vec![3], Vec::new()),
            Err(StorageAccessError::Forbidden)
        );
        assert_eq!(image, before);
        access
            .apply_batch(
                StateLane::Linear,
                &mut image,
                vec![3],
                vec![
                    (b"s/0/a".to_vec(), None),
                    (b"s/0/b".to_vec(), Some(vec![4])),
                    (b"s/0/c".to_vec(), Some(Vec::new())),
                ],
            )
            .unwrap();
        assert_eq!(image.inline(), &[3]);
        assert_eq!(image.row(b"s/0/a"), None);
        assert_eq!(image.row(b"s/0/b"), Some(&[4][..]));
        assert_eq!(image.row(b"s/0/c"), Some(&[][..]));
        assert_eq!(
            ActorLaneImage::decode(&image.encode().unwrap()).unwrap(),
            image
        );
    }

    #[test]
    fn full_images_exchange_rows_atomically_without_transient_capacity() {
        let schema = schema();
        let access = ActorStorageAccess::new(&schema, "method_3", MethodMode::Linear).unwrap();
        let mut image = ActorLaneImage::default();
        image.replace_inline(vec![1; 8]).unwrap();
        for ordinal in 0..63 {
            image
                .write_row(
                    alloc::format!("s/0/{ordinal:05}").into_bytes(),
                    Some(vec![2; MAX_ROW_BYTES]),
                )
                .unwrap();
        }
        let key = b"s/0/00063".to_vec();
        let remaining = MAX_IMAGE_BYTES - image.encoded_len().unwrap() - 8 - key.len();
        image.write_row(key, Some(vec![2; remaining])).unwrap();
        assert_eq!(image.encode().unwrap().len(), MAX_IMAGE_BYTES);
        let before = image.clone();
        let changes = || {
            vec![
                (b"s/0/!swap".to_vec(), Some(vec![3; MAX_ROW_BYTES])),
                (b"s/0/00000".to_vec(), None),
            ]
        };
        assert!(
            access
                .apply_batch(StateLane::Linear, &mut image, vec![1; 9], changes())
                .is_err()
        );
        assert_eq!(image, before);
        access
            .apply_batch(StateLane::Linear, &mut image, vec![4; 8], changes())
            .unwrap();
        assert_eq!(image.encode().unwrap().len(), MAX_IMAGE_BYTES);
        assert_eq!(image.row(b"s/0/00000"), None);
        assert_eq!(image.row(b"s/0/!swap").unwrap(), &[3; MAX_ROW_BYTES]);
        let after = image.clone();
        access
            .apply_batch(StateLane::Linear, &mut image, vec![4; 8], changes())
            .unwrap();
        assert_eq!(image, after, "an exact row delta is idempotent");

        let mut image = ActorLaneImage::default();
        // Construct the maximum-count fixture directly; assert admission
        // before using it so the test does not rely on malformed state.
        for ordinal in 0..MAX_ROWS {
            image
                .rows
                .insert(alloc::format!("s/0/{ordinal:05}").into_bytes(), Vec::new());
        }
        image.encode().unwrap();
        access.validate_image(StateLane::Linear, &image).unwrap();
        let before = image.clone();
        assert!(
            access
                .apply_batch(
                    StateLane::Linear,
                    &mut image,
                    Vec::new(),
                    vec![(b"s/0/!swap".to_vec(), Some(Vec::new())),]
                )
                .is_err()
        );
        assert_eq!(image, before);
        access
            .apply_batch(
                StateLane::Linear,
                &mut image,
                Vec::new(),
                vec![
                    (b"s/0/!swap".to_vec(), Some(Vec::new())),
                    (alloc::format!("s/0/{:05}", MAX_ROWS - 1).into_bytes(), None),
                ],
            )
            .unwrap();
        assert_eq!(image.rows.len(), MAX_ROWS);
        assert_eq!(
            ActorLaneImage::decode(&image.encode().unwrap()).unwrap(),
            image
        );
    }

    #[test]
    fn row_reader_keeps_absence_distinct_from_hidden_or_undeclared_rows() {
        let schema = schema();
        let access = ActorStorageAccess::new(&schema, "method_0", MethodMode::Query).unwrap();
        let reader = ActorStorageReader::new(&access, None, None, None).unwrap();
        assert_eq!(reader.read(b"s/0/missing"), Ok(None));
        assert_eq!(reader.read(b"s/1/missing"), Ok(None));
        assert_eq!(
            reader.read(b"s/2/missing"),
            Err(StorageAccessError::Forbidden)
        );
        assert_eq!(
            reader.read(b"other/key"),
            Err(StorageAccessError::UndeclaredNamespace)
        );
        let mut misplaced = ActorLaneImage::default();
        misplaced
            .write_row(b"s/0/key".to_vec(), Some(vec![1]))
            .unwrap();
        assert!(matches!(
            ActorStorageReader::new(&access, None, None, Some(&misplaced)),
            Err(StorageAccessError::WrongLane)
        ));
    }

    #[test]
    fn every_method_mode_obeys_signed_row_lane_visibility_and_writes() {
        let schema = schema();
        for method in &schema.methods {
            let access = ActorStorageAccess::new(&schema, &method.name, method.mode).unwrap();
            for (index, lane) in [StateLane::Linear, StateLane::Merge, StateLane::Local]
                .into_iter()
                .enumerate()
            {
                let key = alloc::format!("s/{index}/value").into_bytes();
                let mut image = ActorLaneImage::default();
                image.write_row(key.clone(), Some(vec![7])).unwrap();
                access.validate_image(lane, &image).unwrap();
                let before = image.clone();
                let read = access.read(lane, &image, &key);
                if method.mode.can_read(lane) {
                    assert_eq!(read, Ok(Some(&[7][..])));
                } else {
                    assert_eq!(read, Err(StorageAccessError::Forbidden));
                }
                let write = access.write(lane, &mut image, key.clone(), Some(vec![9]));
                if method.mode.can_write(lane) {
                    write.unwrap();
                    assert_eq!(image.row(&key), Some(&[9][..]));
                    access.write(lane, &mut image, key, None).unwrap();
                    assert!(image.rows.is_empty());
                } else {
                    assert_eq!(write, Err(StorageAccessError::Forbidden));
                    assert_eq!(
                        access.write(lane, &mut image, key, None),
                        Err(StorageAccessError::Forbidden)
                    );
                    assert_eq!(image, before);
                }
            }
        }
    }

    #[test]
    fn namespace_scope_rejects_forged_modes_prefixes_and_lane_transplants() {
        use crate::agent_sdk::schema::ParsedField;
        let mut schema = schema();
        assert!(ActorStorageAccess::new(&schema, "missing", MethodMode::Local).is_err());
        assert!(ActorStorageAccess::new(&schema, "method_0", MethodMode::Local).is_err());
        let access = ActorStorageAccess::new(&schema, "method_5", MethodMode::Local).unwrap();
        let mut image = ActorLaneImage::default();
        image
            .write_row(b"s/0/value".to_vec(), Some(vec![8]))
            .unwrap();
        assert_eq!(
            access.validate_image(StateLane::Local, &image),
            Err(StorageAccessError::WrongLane)
        );
        assert_eq!(
            access.read(StateLane::Local, &image, b"s/0/value"),
            Err(StorageAccessError::WrongLane)
        );
        let before = image.clone();
        for key in [
            b"s/other/value".as_slice(),
            b"s/2".as_slice(),
            b"__vos_state".as_slice(),
        ] {
            assert_eq!(
                access.write(StateLane::Local, &mut image, key.to_vec(), Some(vec![1])),
                Err(StorageAccessError::UndeclaredNamespace)
            );
        }
        assert_eq!(image, before);
        if let ParsedField::Storage(field) = &mut schema.fields[1] {
            field.prefix = b"s/0/nested/".to_vec();
        }
        assert!(matches!(
            ActorStorageAccess::new(&schema, "method_0", MethodMode::Query),
            Err(StorageAccessError::InvalidSchema)
        ));
    }

    #[test]
    fn rows_do_not_expand_the_inner_inline_snapshot() {
        let mut image = ActorLaneImage::default();
        image.replace_inline(vec![7; MAX_INLINE_BYTES]).unwrap();
        for ordinal in 0u16..256 {
            image
                .write_row(ordinal.to_be_bytes().to_vec(), Some(vec![3; 300]))
                .unwrap();
        }
        let encoded = image.encode().unwrap();
        assert!(encoded.len() > MAX_INLINE_BYTES);
        assert_eq!(image.inline().len(), MAX_INLINE_BYTES);
        assert_eq!(ActorLaneImage::decode(&encoded).unwrap(), image);
    }

    #[test]
    fn updates_are_bounded_atomic_and_preserve_empty_rows() {
        let mut image = ActorLaneImage::default();
        image.write_row(vec![1], Some(Vec::new())).unwrap();
        assert_eq!(image.row(&[1]), Some(&[][..]));
        let before = image.clone();
        assert!(image.replace_inline(vec![0; MAX_INLINE_BYTES + 1]).is_err());
        assert!(
            image
                .write_row(vec![1], Some(vec![0; MAX_ROW_BYTES + 1]))
                .is_err()
        );
        assert!(image.write_row(Vec::new(), Some(Vec::new())).is_err());
        assert_eq!(image, before);
        image.write_row(vec![1], None).unwrap();
        assert_eq!(image.row(&[1]), None);
    }

    #[test]
    fn image_budget_includes_keys_values_and_framing() {
        let mut image = ActorLaneImage::default();
        for ordinal in 0u16..63 {
            image
                .write_row(ordinal.to_be_bytes().to_vec(), Some(vec![0; MAX_ROW_BYTES]))
                .unwrap();
        }
        let remaining = MAX_IMAGE_BYTES - image.encoded_len().unwrap() - 10;
        image
            .write_row(63u16.to_be_bytes().to_vec(), Some(vec![0; remaining]))
            .unwrap();
        assert_eq!(image.encode().unwrap().len(), MAX_IMAGE_BYTES);
        assert_eq!(
            ActorLaneImage::decode(&image.encode().unwrap()).unwrap(),
            image
        );
        let before = image.clone();
        assert!(
            image
                .write_row(63u16.to_be_bytes().to_vec(), Some(vec![0; remaining + 1]))
                .is_err()
        );
        assert_eq!(image, before);
    }

    #[test]
    fn decoder_rejects_duplicates_order_trailing_bytes_and_unbounded_counts() {
        let mut image = ActorLaneImage::default();
        image.write_row(vec![1], Some(Vec::new())).unwrap();
        image.write_row(vec![2], Some(Vec::new())).unwrap();
        let canonical = image.encode().unwrap();
        for second_key in [0, 1] {
            let mut bad = canonical.clone();
            bad[HEADER_BYTES + 9 + 4] = second_key;
            assert_eq!(ActorLaneImage::decode(&bad), Err(DecodeError::NonCanonical));
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            ActorLaneImage::decode(&trailing),
            Err(DecodeError::TrailingBytes)
        );
        let mut bad = canonical;
        bad[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            ActorLaneImage::decode(&bad),
            Err(DecodeError::LimitExceeded)
        );
        assert!(ActorLaneImage::decode(&vec![0; MAX_IMAGE_BYTES + 1]).is_err());
    }
}
