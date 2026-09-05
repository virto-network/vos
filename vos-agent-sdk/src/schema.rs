//! Canonical AgentActor execution schemas.
//!
//! This is the only clean-generation actor schema. Its wire has no entry-kind
//! discriminator and cannot represent a ServiceActor or Task. Fields occupy
//! one declaration-ordered stream so inline lane codecs and row-backed storage
//! retain their exact source relationship across upgrades.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use vos_protocol::wire::{DecodeError, Decoder, Encoder};

pub use crate::{FieldPersistence, MethodMode, StateLane};
use crate::{Hash, LaneSet, RUNTIME_ABI_ID, RuntimeRequirements};

/// The only accepted clean-generation AgentActor schema magic.
pub const MAGIC: [u8; 4] = *b"AAS1";
/// The only accepted clean-generation AgentActor schema version.
pub const VERSION: u16 = 1;
pub const MAX_FIELDS: usize = 256;
pub const MAX_METHODS: usize = 256;
pub const MAX_ENCODED_BYTES: usize = 16 * 1024;
pub const MAX_NAME_BYTES: usize = crate::MAX_ACTOR_NAME_BYTES;
pub const MAX_TYPE_IDENTITY_BYTES: usize = 512;
pub const MAX_STORAGE_PREFIX_BYTES: usize = crate::MAX_STORAGE_PREFIX_BYTES;
pub const MAX_STORAGE_DOMAIN_BYTES: usize = 128;

/// Compile-time descriptor for a declaration-ordered inline, constant, or
/// skipped actor field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InlineFieldMeta {
    pub source_index: u16,
    pub name: &'static str,
    /// Declaration-context-qualified Rust type identity.
    pub type_identity: &'static str,
    pub persistence: FieldPersistence,
}

/// Compile-time descriptor for a declaration-ordered row-backed storage
/// handle. Storage never enters an inline lane blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageFieldMeta {
    pub source_index: u16,
    pub name: &'static str,
    /// Declaration-context-qualified Rust type identity.
    pub type_identity: &'static str,
    /// Exact physical row prefix, signed verbatim.
    pub prefix: &'static [u8],
    pub lane: StateLane,
    pub committed: bool,
    /// Optional application SMT domains. They must be present as a distinct
    /// pair and are legal only when `committed` is true.
    pub leaf_domain: Option<&'static str>,
    pub node_domain: Option<&'static str>,
}

/// One actor field in exact source declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldMeta {
    Inline(InlineFieldMeta),
    Storage(StorageFieldMeta),
}

impl FieldMeta {
    pub const fn source_index(self) -> u16 {
        match self {
            Self::Inline(field) => field.source_index,
            Self::Storage(field) => field.source_index,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Inline(field) => field.name,
            Self::Storage(field) => field.name,
        }
    }
}

/// Compile-time declaration of one actor method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodMeta {
    pub source_index: u16,
    pub name: &'static str,
    pub mode: MethodMode,
    /// False only when the conventional immutable or single-lane mutation
    /// default was inferred by the macro.
    pub explicit: bool,
}

/// Complete compile-time AgentActor schema consumed by [`encode`].
pub struct SchemaMeta {
    pub fields: &'static [FieldMeta],
    pub methods: &'static [MethodMeta],
}

/// Marker emitted only by `#[messages(agent)]`. `#[actor(agent)]` requires
/// this trait, preventing unrestricted service-style handlers from being
/// packaged behind an AgentActor schema.
#[doc(hidden)]
pub trait AgentMessageSet {
    const ALL_MUTATIONS_EXPLICIT: bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedInlineField {
    pub source_index: u16,
    pub name: String,
    pub type_identity: String,
    pub persistence: FieldPersistence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedStorageField {
    pub source_index: u16,
    pub name: String,
    pub type_identity: String,
    pub prefix: Vec<u8>,
    pub lane: StateLane,
    pub committed: bool,
    pub leaf_domain: Option<String>,
    pub node_domain: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedField {
    Inline(ParsedInlineField),
    Storage(ParsedStorageField),
}

impl ParsedField {
    pub fn source_index(&self) -> u16 {
        match self {
            Self::Inline(field) => field.source_index,
            Self::Storage(field) => field.source_index,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Inline(field) => &field.name,
            Self::Storage(field) => &field.name,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMethod {
    pub source_index: u16,
    pub name: String,
    pub mode: MethodMode,
    pub explicit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedSchema {
    pub fields: Vec<ParsedField>,
    pub methods: Vec<ParsedMethod>,
}

impl ParsedSchema {
    pub fn inline_fields(&self) -> impl Iterator<Item = &ParsedInlineField> {
        self.fields.iter().filter_map(|field| match field {
            ParsedField::Inline(field) => Some(field),
            ParsedField::Storage(_) => None,
        })
    }

    pub fn storage_fields(&self) -> impl Iterator<Item = &ParsedStorageField> {
        self.fields.iter().filter_map(|field| match field {
            ParsedField::Inline(_) => None,
            ParsedField::Storage(field) => Some(field),
        })
    }

    pub fn uses_storage(&self) -> bool {
        self.storage_fields().next().is_some()
    }

    pub fn lanes(&self) -> LaneSet {
        let mut lanes = LaneSet::NONE;
        for field in &self.fields {
            match field {
                ParsedField::Inline(ParsedInlineField {
                    persistence: FieldPersistence::State(lane),
                    ..
                })
                | ParsedField::Storage(ParsedStorageField { lane, .. }) => {
                    lanes = lanes.union(LaneSet::of(*lane));
                }
                ParsedField::Inline(_) => {}
            }
        }
        for method in &self.methods {
            if method.mode == MethodMode::LinearizableQuery {
                lanes = lanes.union(LaneSet::of(StateLane::Linear));
            } else if method.mode == MethodMode::LocalQuery {
                lanes = lanes.union(LaneSet::of(StateLane::Local));
            } else if let Some(lane) = method.mode.write_lane() {
                lanes = lanes.union(LaneSet::of(lane));
            }
        }
        lanes
    }

    pub fn runtime_requirements(&self, scheduling: bool, proofs: bool) -> RuntimeRequirements {
        RuntimeRequirements {
            lanes: self.lanes(),
            scheduling,
            proofs,
        }
    }

    /// Stable identity of the complete declaration-ordered state layout.
    /// Method-only changes do not alter this commitment.
    pub fn state_layout_hash(&self) -> Result<Hash, SchemaError> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        let mut encoder = Encoder(&mut bytes);
        encoder.u16(self.fields.len() as u16);
        for field in &self.fields {
            encode_parsed_field(&mut encoder, field);
        }
        Ok(Hash::digest(b"vos/agent/actor-state-layout", &[&bytes]))
    }

    /// Stable commitment of the entire canonical schema, including methods.
    pub fn schema_hash(&self) -> Result<Hash, SchemaError> {
        Ok(Hash::digest(b"vos/agent/actor-schema", &[&self.encode()?]))
    }

    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.fields.len() > MAX_FIELDS || self.methods.len() > MAX_METHODS {
            return Err(SchemaError::LimitExceeded);
        }
        for (index, field) in self.fields.iter().enumerate() {
            if field.source_index() as usize != index {
                return Err(SchemaError::SourceOrder);
            }
            validate_parsed_field(field)?;
        }
        for (index, method) in self.methods.iter().enumerate() {
            if method.source_index as usize != index {
                return Err(SchemaError::SourceOrder);
            }
            if !valid_name(&method.name) {
                return Err(SchemaError::InvalidMethod);
            }
        }
        if duplicate_field_names(&self.fields) || duplicate_method_names(&self.methods) {
            return Err(SchemaError::DuplicateName);
        }
        if overlapping_storage_prefixes(&self.fields) {
            return Err(SchemaError::OverlappingPrefix);
        }
        let mixed = self.field_lanes().bits().count_ones() > 1;
        if mixed
            && self.methods.iter().any(|method| {
                !method.explicit
                    && !matches!(
                        method.mode,
                        MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::LocalQuery
                    )
            })
        {
            return Err(SchemaError::InvalidMethod);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, SchemaError> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve(MAX_ENCODED_BYTES.min(4096))
            .map_err(|_| SchemaError::LimitExceeded)?;
        bytes.extend_from_slice(&MAGIC);
        let mut encoder = Encoder(&mut bytes);
        encoder.u16(VERSION);
        encoder.fixed(RUNTIME_ABI_ID.as_bytes());
        encoder.u16(self.fields.len() as u16);
        for field in &self.fields {
            encode_parsed_field(&mut encoder, field);
        }
        encoder.u16(self.methods.len() as u16);
        for method in &self.methods {
            encode_parsed_method(&mut encoder, method);
        }
        if bytes.len() > MAX_ENCODED_BYTES {
            return Err(SchemaError::LimitExceeded);
        }
        Ok(bytes)
    }

    fn field_lanes(&self) -> LaneSet {
        self.fields.iter().fold(LaneSet::NONE, |lanes, field| {
            let lane = match field {
                ParsedField::Inline(ParsedInlineField {
                    persistence: FieldPersistence::State(lane),
                    ..
                })
                | ParsedField::Storage(ParsedStorageField { lane, .. }) => Some(*lane),
                ParsedField::Inline(_) => None,
            };
            lane.map_or(lanes, |lane| lanes.union(LaneSet::of(lane)))
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaError {
    Decode(DecodeError),
    InvalidField,
    InvalidMethod,
    DuplicateName,
    SourceOrder,
    OverlappingPrefix,
    LimitExceeded,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(formatter),
            Self::InvalidField => formatter.write_str("invalid AgentActor schema field"),
            Self::InvalidMethod => formatter.write_str("invalid AgentActor schema method"),
            Self::DuplicateName => formatter.write_str("duplicate AgentActor schema name"),
            Self::SourceOrder => formatter.write_str("noncanonical source declaration order"),
            Self::OverlappingPrefix => formatter.write_str("overlapping actor storage prefixes"),
            Self::LimitExceeded => formatter.write_str("AgentActor schema limit exceeded"),
        }
    }
}

impl core::error::Error for SchemaError {}

impl From<DecodeError> for SchemaError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

/// Allocation-free encoder used by actor macros in guest builds.
pub const fn encode<const N: usize>(schema: &SchemaMeta) -> ([u8; N], usize) {
    assert!(N <= MAX_ENCODED_BYTES);
    assert_valid_meta(schema);
    let mut output = [0u8; N];
    let mut position = 0usize;
    position = write_bytes_unframed(&mut output, position, &MAGIC);
    position = write_bytes_unframed(&mut output, position, &VERSION.to_le_bytes());
    position = write_bytes_unframed(&mut output, position, RUNTIME_ABI_ID.as_bytes());
    position = write_u16(&mut output, position, schema.fields.len() as u16);
    let mut field_position = 0usize;
    while field_position < schema.fields.len() {
        position = encode_meta_field(&mut output, position, schema.fields[field_position]);
        field_position += 1;
    }
    position = write_u16(&mut output, position, schema.methods.len() as u16);
    let mut method_index = 0usize;
    while method_index < schema.methods.len() {
        let method = schema.methods[method_index];
        position = write_u16(&mut output, position, method.source_index);
        position = write_str(&mut output, position, method.name);
        output[position] = encode_mode(method.mode);
        output[position + 1] = method.explicit as u8;
        position += 2;
        method_index += 1;
    }
    assert!(position <= MAX_ENCODED_BYTES);
    (output, position)
}

pub fn decode(input: &[u8]) -> Result<ParsedSchema, SchemaError> {
    if input.len() > MAX_ENCODED_BYTES {
        return Err(SchemaError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    if decoder.take(MAGIC.len())? != MAGIC {
        return Err(DecodeError::InvalidTag.into());
    }
    if decoder.u16()? != VERSION {
        return Err(DecodeError::InvalidTag.into());
    }
    if Hash(decoder.fixed()?) != RUNTIME_ABI_ID {
        return Err(DecodeError::InvalidPlatform.into());
    }
    let field_count = decoder.u16()? as usize;
    if field_count > MAX_FIELDS {
        return Err(SchemaError::LimitExceeded);
    }
    let mut fields = Vec::new();
    fields
        .try_reserve_exact(field_count)
        .map_err(|_| SchemaError::LimitExceeded)?;
    for expected_index in 0..field_count {
        let source_index = decoder.u16()?;
        if source_index as usize != expected_index {
            return Err(SchemaError::SourceOrder);
        }
        fields.push(decode_field(&mut decoder, source_index)?);
    }
    let method_count = decoder.u16()? as usize;
    if method_count > MAX_METHODS {
        return Err(SchemaError::LimitExceeded);
    }
    let mut methods = Vec::new();
    methods
        .try_reserve_exact(method_count)
        .map_err(|_| SchemaError::LimitExceeded)?;
    for expected_index in 0..method_count {
        let source_index = decoder.u16()?;
        if source_index as usize != expected_index {
            return Err(SchemaError::SourceOrder);
        }
        methods.push(ParsedMethod {
            source_index,
            name: decoder.string_bounded(MAX_NAME_BYTES)?,
            mode: decode_mode(decoder.u8()?)?,
            explicit: decoder.bool()?,
        });
    }
    if !decoder.exhausted() {
        return Err(DecodeError::TrailingBytes.into());
    }
    let schema = ParsedSchema { fields, methods };
    schema.validate()?;
    if schema.encode()?.as_slice() != input {
        return Err(DecodeError::NonCanonical.into());
    }
    Ok(schema)
}

fn decode_field(decoder: &mut Decoder<'_>, source_index: u16) -> Result<ParsedField, SchemaError> {
    match decoder.u8()? {
        0 => Ok(ParsedField::Inline(ParsedInlineField {
            source_index,
            name: decoder.string_bounded(MAX_NAME_BYTES)?,
            type_identity: decoder.string_bounded(MAX_TYPE_IDENTITY_BYTES)?,
            persistence: decode_persistence(decoder.u8()?)?,
        })),
        1 => {
            let name = decoder.string_bounded(MAX_NAME_BYTES)?;
            let type_identity = decoder.string_bounded(MAX_TYPE_IDENTITY_BYTES)?;
            let prefix = decoder.bytes_bounded(MAX_STORAGE_PREFIX_BYTES)?;
            let lane = decode_lane(decoder.u8()?)?;
            let committed = decoder.bool()?;
            let domains = decoder.bool()?;
            let (leaf_domain, node_domain) = if domains {
                (
                    Some(decoder.string_bounded(MAX_STORAGE_DOMAIN_BYTES)?),
                    Some(decoder.string_bounded(MAX_STORAGE_DOMAIN_BYTES)?),
                )
            } else {
                (None, None)
            };
            Ok(ParsedField::Storage(ParsedStorageField {
                source_index,
                name,
                type_identity,
                prefix,
                lane,
                committed,
                leaf_domain,
                node_domain,
            }))
        }
        _ => Err(DecodeError::InvalidTag.into()),
    }
}

fn validate_parsed_field(field: &ParsedField) -> Result<(), SchemaError> {
    match field {
        ParsedField::Inline(field) => {
            if !valid_name(&field.name) || !valid_type_identity(&field.type_identity) {
                return Err(SchemaError::InvalidField);
            }
        }
        ParsedField::Storage(field) => {
            if !valid_name(&field.name)
                || !valid_type_identity(&field.type_identity)
                || !valid_storage_prefix(&field.prefix)
                || !valid_domains(
                    field.committed,
                    field.leaf_domain.as_deref(),
                    field.node_domain.as_deref(),
                )
            {
                return Err(SchemaError::InvalidField);
            }
        }
    }
    Ok(())
}

fn duplicate_field_names(fields: &[ParsedField]) -> bool {
    fields.iter().enumerate().any(|(index, field)| {
        fields[index + 1..]
            .iter()
            .any(|other| field.name() == other.name())
    })
}

fn duplicate_method_names(methods: &[ParsedMethod]) -> bool {
    methods.iter().enumerate().any(|(index, method)| {
        methods[index + 1..]
            .iter()
            .any(|other| method.name == other.name)
    })
}

fn overlapping_storage_prefixes(fields: &[ParsedField]) -> bool {
    fields.iter().enumerate().any(|(index, field)| {
        let ParsedField::Storage(field) = field else {
            return false;
        };
        fields[index + 1..].iter().any(|other| {
            let ParsedField::Storage(other) = other else {
                return false;
            };
            field.prefix.starts_with(&other.prefix) || other.prefix.starts_with(&field.prefix)
        })
    })
}

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_NAME_BYTES
}

fn valid_type_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TYPE_IDENTITY_BYTES
        && value.as_bytes().windows(2).any(|pair| pair == b"::")
}

fn valid_storage_prefix(prefix: &[u8]) -> bool {
    !prefix.is_empty()
        && prefix.len() <= MAX_STORAGE_PREFIX_BYTES
        && prefix[0] != 0
        && !prefix.starts_with(b"__vos_")
}

fn valid_domains(committed: bool, leaf: Option<&str>, node: Option<&str>) -> bool {
    match (leaf, node) {
        (None, None) => true,
        (Some(leaf), Some(node)) => {
            committed
                && !leaf.is_empty()
                && leaf.len() <= MAX_STORAGE_DOMAIN_BYTES
                && !node.is_empty()
                && node.len() <= MAX_STORAGE_DOMAIN_BYTES
                && leaf != node
        }
        _ => false,
    }
}

fn encode_parsed_field(encoder: &mut Encoder<'_>, field: &ParsedField) {
    encoder.u16(field.source_index());
    match field {
        ParsedField::Inline(field) => {
            encoder.u8(0);
            encoder.string(&field.name);
            encoder.string(&field.type_identity);
            encoder.u8(encode_persistence(field.persistence));
        }
        ParsedField::Storage(field) => {
            encoder.u8(1);
            encoder.string(&field.name);
            encoder.string(&field.type_identity);
            encoder.bytes(&field.prefix);
            encoder.u8(encode_lane(field.lane));
            encoder.bool(field.committed);
            match (&field.leaf_domain, &field.node_domain) {
                (Some(leaf), Some(node)) => {
                    encoder.bool(true);
                    encoder.string(leaf);
                    encoder.string(node);
                }
                (None, None) => encoder.bool(false),
                _ => unreachable!("validated storage domains are paired"),
            }
        }
    }
}

fn encode_parsed_method(encoder: &mut Encoder<'_>, method: &ParsedMethod) {
    encoder.u16(method.source_index);
    encoder.string(&method.name);
    encoder.u8(encode_mode(method.mode));
    encoder.bool(method.explicit);
}

const fn assert_valid_meta(schema: &SchemaMeta) {
    assert!(schema.fields.len() <= MAX_FIELDS);
    assert!(schema.methods.len() <= MAX_METHODS);
    let mut lanes = 0u8;
    let mut field_index = 0usize;
    while field_index < schema.fields.len() {
        let field = schema.fields[field_index];
        assert!(field.source_index() as usize == field_index);
        assert!(valid_meta_name(field.name()));
        match field {
            FieldMeta::Inline(field) => {
                assert!(valid_meta_type_identity(field.type_identity));
                if let FieldPersistence::State(lane) = field.persistence {
                    lanes |= lane_bit(lane);
                }
            }
            FieldMeta::Storage(field) => {
                assert!(valid_meta_type_identity(field.type_identity));
                assert!(valid_meta_storage_prefix(field.prefix));
                assert!(valid_meta_domains(
                    field.committed,
                    field.leaf_domain,
                    field.node_domain,
                ));
                lanes |= lane_bit(field.lane);
            }
        }
        let mut previous = 0usize;
        while previous < field_index {
            assert!(!bytes_equal(
                schema.fields[previous].name().as_bytes(),
                field.name().as_bytes(),
            ));
            if let (FieldMeta::Storage(left), FieldMeta::Storage(right)) =
                (schema.fields[previous], field)
            {
                assert!(!prefixes_overlap(left.prefix, right.prefix));
            }
            previous += 1;
        }
        field_index += 1;
    }

    let mixed = lanes.count_ones() > 1;
    let mut method_index = 0usize;
    while method_index < schema.methods.len() {
        let method = schema.methods[method_index];
        assert!(method.source_index as usize == method_index);
        assert!(valid_meta_name(method.name));
        if mixed && !method.explicit {
            assert!(matches!(
                method.mode,
                MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::LocalQuery
            ));
        }
        let mut previous = 0usize;
        while previous < method_index {
            assert!(!bytes_equal(
                schema.methods[previous].name.as_bytes(),
                method.name.as_bytes(),
            ));
            previous += 1;
        }
        method_index += 1;
    }
}

const fn valid_meta_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_NAME_BYTES
}

const fn valid_meta_type_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TYPE_IDENTITY_BYTES
        && contains_double_colon(value.as_bytes())
}

const fn contains_double_colon(value: &[u8]) -> bool {
    let mut index = 1usize;
    while index < value.len() {
        if value[index - 1] == b':' && value[index] == b':' {
            return true;
        }
        index += 1;
    }
    false
}

const fn valid_meta_storage_prefix(prefix: &[u8]) -> bool {
    !prefix.is_empty()
        && prefix.len() <= MAX_STORAGE_PREFIX_BYTES
        && prefix[0] != 0
        && !starts_with(prefix, b"__vos_")
}

const fn valid_meta_domains(committed: bool, leaf: Option<&str>, node: Option<&str>) -> bool {
    match (leaf, node) {
        (None, None) => true,
        (Some(leaf), Some(node)) => {
            committed
                && !leaf.is_empty()
                && leaf.len() <= MAX_STORAGE_DOMAIN_BYTES
                && !node.is_empty()
                && node.len() <= MAX_STORAGE_DOMAIN_BYTES
                && !bytes_equal(leaf.as_bytes(), node.as_bytes())
        }
        _ => false,
    }
}

const fn lane_bit(lane: StateLane) -> u8 {
    match lane {
        StateLane::Linear => 1,
        StateLane::Merge => 2,
        StateLane::Local => 4,
    }
}

const fn bytes_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut index = 0usize;
    while index < left.len() {
        if left[index] != right[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn starts_with(value: &[u8], prefix: &[u8]) -> bool {
    if value.len() < prefix.len() {
        return false;
    }
    let mut index = 0usize;
    while index < prefix.len() {
        if value[index] != prefix[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn prefixes_overlap(left: &[u8], right: &[u8]) -> bool {
    starts_with(left, right) || starts_with(right, left)
}

const fn encode_meta_field<const N: usize>(
    output: &mut [u8; N],
    mut position: usize,
    field: FieldMeta,
) -> usize {
    position = write_u16(output, position, field.source_index());
    match field {
        FieldMeta::Inline(field) => {
            output[position] = 0;
            position += 1;
            position = write_str(output, position, field.name);
            position = write_str(output, position, field.type_identity);
            output[position] = encode_persistence(field.persistence);
            position + 1
        }
        FieldMeta::Storage(field) => {
            output[position] = 1;
            position += 1;
            position = write_str(output, position, field.name);
            position = write_str(output, position, field.type_identity);
            position = write_bytes(output, position, field.prefix);
            output[position] = encode_lane(field.lane);
            output[position + 1] = field.committed as u8;
            position += 2;
            match (field.leaf_domain, field.node_domain) {
                (Some(leaf), Some(node)) => {
                    output[position] = 1;
                    position += 1;
                    position = write_str(output, position, leaf);
                    write_str(output, position, node)
                }
                (None, None) => {
                    output[position] = 0;
                    position + 1
                }
                _ => panic!("storage domains must be paired"),
            }
        }
    }
}

const fn write_u16<const N: usize>(output: &mut [u8; N], position: usize, value: u16) -> usize {
    write_bytes_unframed(output, position, &value.to_le_bytes())
}

const fn write_str<const N: usize>(output: &mut [u8; N], position: usize, value: &str) -> usize {
    write_bytes(output, position, value.as_bytes())
}

const fn write_bytes<const N: usize>(
    output: &mut [u8; N],
    mut position: usize,
    bytes: &[u8],
) -> usize {
    position = write_bytes_unframed(output, position, &(bytes.len() as u32).to_le_bytes());
    write_bytes_unframed(output, position, bytes)
}

const fn write_bytes_unframed<const N: usize>(
    output: &mut [u8; N],
    position: usize,
    bytes: &[u8],
) -> usize {
    assert!(position + bytes.len() <= N);
    let mut index = 0usize;
    while index < bytes.len() {
        output[position + index] = bytes[index];
        index += 1;
    }
    position + bytes.len()
}

const fn encode_persistence(value: FieldPersistence) -> u8 {
    match value {
        FieldPersistence::State(StateLane::Linear) => 0,
        FieldPersistence::State(StateLane::Merge) => 1,
        FieldPersistence::State(StateLane::Local) => 2,
        FieldPersistence::Constant => 3,
        FieldPersistence::Skipped => 4,
    }
}

fn decode_persistence(value: u8) -> Result<FieldPersistence, SchemaError> {
    match value {
        0 => Ok(FieldPersistence::State(StateLane::Linear)),
        1 => Ok(FieldPersistence::State(StateLane::Merge)),
        2 => Ok(FieldPersistence::State(StateLane::Local)),
        3 => Ok(FieldPersistence::Constant),
        4 => Ok(FieldPersistence::Skipped),
        _ => Err(DecodeError::InvalidTag.into()),
    }
}

const fn encode_lane(value: StateLane) -> u8 {
    match value {
        StateLane::Linear => 0,
        StateLane::Merge => 1,
        StateLane::Local => 2,
    }
}

fn decode_lane(value: u8) -> Result<StateLane, SchemaError> {
    match value {
        0 => Ok(StateLane::Linear),
        1 => Ok(StateLane::Merge),
        2 => Ok(StateLane::Local),
        _ => Err(DecodeError::InvalidTag.into()),
    }
}

const fn encode_mode(value: MethodMode) -> u8 {
    match value {
        MethodMode::Query => 0,
        MethodMode::LinearizableQuery => 1,
        MethodMode::LocalQuery => 2,
        MethodMode::Linear => 3,
        MethodMode::Merge => 4,
        MethodMode::Local => 5,
    }
}

fn decode_mode(value: u8) -> Result<MethodMode, SchemaError> {
    match value {
        0 => Ok(MethodMode::Query),
        1 => Ok(MethodMode::LinearizableQuery),
        2 => Ok(MethodMode::LocalQuery),
        3 => Ok(MethodMode::Linear),
        4 => Ok(MethodMode::Merge),
        5 => Ok(MethodMode::Local),
        _ => Err(DecodeError::InvalidTag.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELDS: &[FieldMeta] = &[
        FieldMeta::Inline(InlineFieldMeta {
            source_index: 0,
            name: "title",
            type_identity: "example::String",
            persistence: FieldPersistence::State(StateLane::Linear),
        }),
        FieldMeta::Storage(StorageFieldMeta {
            source_index: 1,
            name: "rows",
            type_identity: "example::StorageMap<u64,u64>",
            prefix: b"rows/",
            lane: StateLane::Merge,
            committed: true,
            leaf_domain: Some("example/smt/leaf/v1"),
            node_domain: Some("example/smt/node/v1"),
        }),
        FieldMeta::Inline(InlineFieldMeta {
            source_index: 2,
            name: "configuration",
            type_identity: "example::Configuration",
            persistence: FieldPersistence::Constant,
        }),
    ];
    const METHODS: &[MethodMeta] = &[
        MethodMeta {
            source_index: 0,
            name: "rename",
            mode: MethodMode::Linear,
            explicit: true,
        },
        MethodMeta {
            source_index: 1,
            name: "insert",
            mode: MethodMode::Merge,
            explicit: true,
        },
        MethodMeta {
            source_index: 2,
            name: "read",
            mode: MethodMode::Query,
            explicit: false,
        },
    ];
    const SCHEMA: SchemaMeta = SchemaMeta {
        fields: FIELDS,
        methods: METHODS,
    };
    const ENCODED: ([u8; 2048], usize) = encode::<2048>(&SCHEMA);

    fn parsed() -> ParsedSchema {
        decode(&ENCODED.0[..ENCODED.1]).unwrap()
    }

    fn encode_unchecked(schema: &ParsedSchema) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        let mut encoder = Encoder(&mut bytes);
        encoder.u16(VERSION);
        encoder.fixed(RUNTIME_ABI_ID.as_bytes());
        encoder.u16(schema.fields.len() as u16);
        for field in &schema.fields {
            encode_parsed_field(&mut encoder, field);
        }
        encoder.u16(schema.methods.len() as u16);
        for method in &schema.methods {
            encode_parsed_method(&mut encoder, method);
        }
        bytes
    }

    fn inline(
        source_index: u16,
        name: &str,
        type_identity: &str,
        persistence: FieldPersistence,
    ) -> ParsedField {
        ParsedField::Inline(ParsedInlineField {
            source_index,
            name: name.into(),
            type_identity: type_identity.into(),
            persistence,
        })
    }

    fn storage(source_index: u16, name: &str, prefix: &[u8]) -> ParsedField {
        ParsedField::Storage(ParsedStorageField {
            source_index,
            name: name.into(),
            type_identity: "example::StorageMap<u64,u64>".into(),
            prefix: prefix.into(),
            lane: StateLane::Merge,
            committed: false,
            leaf_domain: None,
            node_domain: None,
        })
    }

    #[test]
    fn const_and_owned_encoders_round_trip_byte_identically() {
        let schema = parsed();
        assert_eq!(schema.encode().unwrap(), &ENCODED.0[..ENCODED.1]);
        assert_eq!(schema.fields.len(), 3);
        assert!(matches!(schema.fields[0], ParsedField::Inline(_)));
        assert!(matches!(schema.fields[1], ParsedField::Storage(_)));
        assert!(matches!(schema.fields[2], ParsedField::Inline(_)));
        assert_eq!(schema.inline_fields().count(), 2);
        assert_eq!(schema.storage_fields().count(), 1);
        assert!(schema.uses_storage());
        assert!(
            schema
                .inline_fields()
                .all(|field| field.type_identity.contains("::"))
        );
    }

    #[test]
    fn lanes_and_runtime_requirements_include_fields_and_method_modes() {
        let schema = parsed();
        let lanes = LaneSet::of(StateLane::Linear).union(LaneSet::of(StateLane::Merge));
        assert_eq!(schema.lanes(), lanes);
        assert_eq!(
            schema.runtime_requirements(true, true),
            RuntimeRequirements {
                lanes,
                scheduling: true,
                proofs: true,
            }
        );

        let local_query = ParsedSchema {
            fields: Vec::new(),
            methods: alloc::vec![ParsedMethod {
                source_index: 0,
                name: "read_local".into(),
                mode: MethodMode::LocalQuery,
                explicit: true,
            }],
        };
        assert_eq!(local_query.lanes(), LaneSet::of(StateLane::Local));
    }

    #[test]
    fn state_layout_and_whole_schema_commitments_have_separate_domains() {
        let schema = parsed();
        let layout = schema.state_layout_hash().unwrap();
        let whole = schema.schema_hash().unwrap();
        assert_ne!(layout, whole);

        let mut method_change = schema.clone();
        method_change.methods[2].name = "inspect".into();
        assert_eq!(method_change.state_layout_hash().unwrap(), layout);
        assert_ne!(method_change.schema_hash().unwrap(), whole);

        let mut state_change = schema;
        let ParsedField::Inline(field) = &mut state_change.fields[0] else {
            unreachable!();
        };
        field.type_identity = "example::Text".into();
        assert_ne!(state_change.state_layout_hash().unwrap(), layout);
        assert_ne!(state_change.schema_hash().unwrap(), whole);
    }

    #[test]
    fn duplicate_names_prefix_aliases_and_source_reordering_are_rejected() {
        let mut duplicate_field = parsed();
        let name = String::from(duplicate_field.fields[0].name());
        let ParsedField::Storage(field) = &mut duplicate_field.fields[1] else {
            unreachable!();
        };
        field.name = name;
        assert_eq!(duplicate_field.validate(), Err(SchemaError::DuplicateName));
        assert_eq!(
            duplicate_field.state_layout_hash(),
            Err(SchemaError::DuplicateName)
        );
        assert_eq!(
            decode(&encode_unchecked(&duplicate_field)),
            Err(SchemaError::DuplicateName)
        );

        let mut duplicate_method = parsed();
        duplicate_method.methods[1].name = duplicate_method.methods[0].name.clone();
        assert_eq!(duplicate_method.validate(), Err(SchemaError::DuplicateName));
        assert_eq!(
            decode(&encode_unchecked(&duplicate_method)),
            Err(SchemaError::DuplicateName)
        );

        let overlapping = ParsedSchema {
            fields: alloc::vec![
                storage(0, "rows", b"rows/"),
                storage(1, "child", b"rows/a/")
            ],
            methods: alloc::vec![ParsedMethod {
                source_index: 0,
                name: "write".into(),
                mode: MethodMode::Merge,
                explicit: true,
            }],
        };
        assert_eq!(overlapping.validate(), Err(SchemaError::OverlappingPrefix));
        assert_eq!(
            decode(&encode_unchecked(&overlapping)),
            Err(SchemaError::OverlappingPrefix)
        );

        let mut reordered = parsed();
        reordered.fields.swap(0, 1);
        assert_eq!(reordered.validate(), Err(SchemaError::SourceOrder));

        let mut bytes = ENCODED.0[..ENCODED.1].to_vec();
        let first_source_index = 4 + 2 + 32 + 2;
        bytes[first_source_index..first_source_index + 2].copy_from_slice(&1u16.to_le_bytes());
        assert_eq!(decode(&bytes), Err(SchemaError::SourceOrder));
    }

    #[test]
    fn storage_prefix_and_commitment_domains_are_strict() {
        for prefix in [b"".as_slice(), b"\0private/", b"__vos_rows/"] {
            let schema = ParsedSchema {
                fields: alloc::vec![storage(0, "rows", prefix)],
                methods: alloc::vec![ParsedMethod {
                    source_index: 0,
                    name: "write".into(),
                    mode: MethodMode::Merge,
                    explicit: true,
                }],
            };
            assert_eq!(schema.validate(), Err(SchemaError::InvalidField));
        }

        let mut schema = parsed();
        if let ParsedField::Storage(field) = &mut schema.fields[1] {
            field.committed = false;
        }
        assert_eq!(schema.validate(), Err(SchemaError::InvalidField));
        assert_eq!(
            decode(&encode_unchecked(&schema)),
            Err(SchemaError::InvalidField)
        );
        if let ParsedField::Storage(field) = &mut schema.fields[1] {
            field.committed = true;
            field.node_domain = None;
        }
        assert_eq!(schema.validate(), Err(SchemaError::InvalidField));
        if let ParsedField::Storage(field) = &mut schema.fields[1] {
            field.node_domain = field.leaf_domain.clone();
        }
        assert_eq!(schema.validate(), Err(SchemaError::InvalidField));
        if let ParsedField::Storage(field) = &mut schema.fields[1] {
            field.leaf_domain = None;
            field.node_domain = None;
        }
        assert!(schema.validate().is_ok(), "committed domains are optional");
    }

    #[test]
    fn mixed_lane_mutations_require_explicit_method_modes() {
        let mut schema = parsed();
        schema.methods[0].explicit = false;
        assert_eq!(schema.validate(), Err(SchemaError::InvalidMethod));
        schema.methods[0].mode = MethodMode::Query;
        assert!(schema.validate().is_ok());
    }

    #[test]
    fn decoder_rejects_old_magic_unknown_tags_hostile_lengths_and_trailing_bytes() {
        let original = ENCODED.0[..ENCODED.1].to_vec();

        let mut old = original.clone();
        old[..4].copy_from_slice(b"AGS2");
        assert_eq!(
            decode(&old),
            Err(SchemaError::Decode(DecodeError::InvalidTag))
        );

        let mut version = original.clone();
        version[4..6].copy_from_slice(&(VERSION + 1).to_le_bytes());
        assert_eq!(
            decode(&version),
            Err(SchemaError::Decode(DecodeError::InvalidTag))
        );

        let mut wrong_runtime_abi = original.clone();
        wrong_runtime_abi[6] ^= 1;
        assert_eq!(
            decode(&wrong_runtime_abi),
            Err(SchemaError::Decode(DecodeError::InvalidPlatform))
        );

        let field_tag = 4 + 2 + 32 + 2 + 2;
        let mut unknown_field = original.clone();
        unknown_field[field_tag] = 9;
        assert_eq!(
            decode(&unknown_field),
            Err(SchemaError::Decode(DecodeError::InvalidTag))
        );

        let first_type = b"example::String";
        let first_type_start = original
            .windows(first_type.len())
            .position(|window| window == first_type)
            .unwrap();
        let mut unknown_persistence = original.clone();
        unknown_persistence[first_type_start + first_type.len()] = 9;
        assert_eq!(
            decode(&unknown_persistence),
            Err(SchemaError::Decode(DecodeError::InvalidTag))
        );

        let prefix = b"rows/";
        let prefix_start = original
            .windows(prefix.len())
            .position(|window| window == prefix)
            .unwrap();
        let mut unknown_lane = original.clone();
        unknown_lane[prefix_start + prefix.len()] = 9;
        assert_eq!(
            decode(&unknown_lane),
            Err(SchemaError::Decode(DecodeError::InvalidTag))
        );

        let leaf = b"example/smt/leaf/v1";
        let leaf_start = original
            .windows(leaf.len())
            .position(|window| window == leaf)
            .unwrap();
        let mut noncanonical_domains = original.clone();
        noncanonical_domains[leaf_start - 5] = 2;
        assert_eq!(
            decode(&noncanonical_domains),
            Err(SchemaError::Decode(DecodeError::NonCanonical))
        );

        let first_name_length = field_tag + 1;
        let mut hostile_length = original.clone();
        hostile_length[first_name_length..first_name_length + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode(&hostile_length),
            Err(SchemaError::Decode(DecodeError::LimitExceeded))
        );

        let mut unknown_mode = original.clone();
        let last_mode = unknown_mode.len() - 2;
        unknown_mode[last_mode] = 9;
        assert_eq!(
            decode(&unknown_mode),
            Err(SchemaError::Decode(DecodeError::InvalidTag))
        );

        let mut noncanonical_bool = original.clone();
        let last_bool = noncanonical_bool.len() - 1;
        noncanonical_bool[last_bool] = 2;
        assert_eq!(
            decode(&noncanonical_bool),
            Err(SchemaError::Decode(DecodeError::NonCanonical))
        );

        let mut trailing = original;
        trailing.push(0);
        assert_eq!(
            decode(&trailing),
            Err(SchemaError::Decode(DecodeError::TrailingBytes))
        );
    }

    #[test]
    fn decoder_and_encoder_enforce_cardinality_and_wire_bounds() {
        let mut methodless = parsed();
        methodless.methods.clear();
        assert!(methodless.validate().is_ok());
        let encoded = methodless.encode().unwrap();
        assert_eq!(decode(&encoded).unwrap(), methodless);

        const EMPTY_META: SchemaMeta = SchemaMeta {
            fields: &[],
            methods: &[],
        };
        const EMPTY_ENCODED: ([u8; 64], usize) = encode::<64>(&EMPTY_META);
        let empty = decode(&EMPTY_ENCODED.0[..EMPTY_ENCODED.1]).unwrap();
        assert!(empty.fields.is_empty());
        assert!(empty.methods.is_empty());

        let mut hostile_count = Vec::new();
        hostile_count.extend_from_slice(&MAGIC);
        hostile_count.extend_from_slice(&VERSION.to_le_bytes());
        hostile_count.extend_from_slice(RUNTIME_ABI_ID.as_bytes());
        hostile_count.extend_from_slice(&((MAX_FIELDS + 1) as u16).to_le_bytes());
        assert_eq!(decode(&hostile_count), Err(SchemaError::LimitExceeded));

        let mut oversized = ENCODED.0[..ENCODED.1].to_vec();
        oversized.resize(MAX_ENCODED_BYTES + 1, 0);
        assert_eq!(decode(&oversized), Err(SchemaError::LimitExceeded));
    }

    #[test]
    fn unqualified_type_identity_is_not_a_schema_contract() {
        let schema = ParsedSchema {
            fields: alloc::vec![inline(
                0,
                "value",
                "u64",
                FieldPersistence::State(StateLane::Linear),
            )],
            methods: alloc::vec![ParsedMethod {
                source_index: 0,
                name: "read".into(),
                mode: MethodMode::Query,
                explicit: false,
            }],
        };
        assert_eq!(schema.validate(), Err(SchemaError::InvalidField));
    }

    #[test]
    #[should_panic]
    fn const_encoder_rejects_noncanonical_source_order() {
        const BAD: SchemaMeta = SchemaMeta {
            fields: &[FieldMeta::Inline(InlineFieldMeta {
                source_index: 1,
                name: "value",
                type_identity: "example::u64",
                persistence: FieldPersistence::State(StateLane::Linear),
            })],
            methods: &[MethodMeta {
                source_index: 0,
                name: "read",
                mode: MethodMode::Query,
                explicit: false,
            }],
        };
        let _ = encode::<512>(&BAD);
    }
}
