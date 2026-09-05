//! Signed actor execution schema used by agent runtimes.
//!
//! The public `.vos_meta` section describes the call surface. This separate
//! `.vos_agent` section describes persistence and ordering: every field has a
//! lane and every method has one execution mode. Keeping the two contracts
//! separate lets HTTP/SSH tooling read schemas without learning runtime
//! internals, while an agent package authenticates both.

use alloc::string::String;
use alloc::vec::Vec;

use super::{FieldPersistence, LaneSet, MethodMode, RuntimeRequirements, StateLane};
use crate::service::Hash;
use crate::service::wire::Encoder;

pub const MAGIC: [u8; 4] = *b"AGS2";
pub const MAX_FIELDS: usize = 256;
pub const MAX_METHODS: usize = 256;
pub const MAX_ENCODED_BYTES: usize = 16 * 1024;
pub const MAX_NAME_BYTES: usize = 128;
pub const MAX_CODEC_BYTES: usize = 512;
pub const MAX_TYPE_IDENTITY_BYTES: usize = 512;
pub const MAX_STORAGE_PREFIX_BYTES: usize = 128;
pub const MAX_STORAGE_DOMAIN_BYTES: usize = 128;

/// ABI selected by the program's process entry point.
///
/// The service host and the standard agent host use different process-entry
/// and hostcall contracts. Task programs use a third, witness-delivered
/// contract. The marker is emitted by the `vos` dependency selected for the
/// guest build, so a packaging command cannot safely relabel one as another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExecutionEntryKind {
    /// Generic service/root-tree actor entry. Value zero preserves packages
    /// emitted before the service/agent split, which all targeted this host.
    ServiceActor = 0,
    /// Witness-delivered Task entry. Its established value remains stable for
    /// production Task identities.
    Task = 1,
    /// Standard agent-runtime actor entry.
    AgentActor = 2,
}

/// Compile-time field descriptor emitted by `#[actor]`.
pub struct FieldMeta {
    pub name: &'static str,
    /// Canonical source spelling of the persisted field codec/type. This is
    /// part of the durable lane layout and prevents package upgrades from
    /// silently reinterpreting declaration-ordered bytes.
    pub codec: &'static str,
    pub persistence: FieldPersistence,
}

/// Compile-time descriptor for one row-backed `#[storage]` handle.
///
/// Storage is deliberately separate from [`FieldMeta`]: a handle does not
/// enter an inline lane blob, while its physical keyspace and commitment
/// policy still form part of the signed actor state layout.
pub struct StorageFieldMeta {
    pub name: &'static str,
    /// Declaration-context-qualified Rust type identity. A later SDK adapter
    /// may split this into kind and key/value schema hashes, but must not
    /// reinterpret or discard it silently.
    pub type_identity: &'static str,
    pub lane: StateLane,
    /// Exact physical row prefix. It is signed verbatim and must remain stable
    /// across field renames unless an explicit storage migration is performed.
    pub prefix: &'static [u8],
    pub committed: bool,
    /// Optional application-owned SMT domains. These are a pair and are valid
    /// only for committed storage.
    pub leaf_domain: Option<&'static str>,
    pub node_domain: Option<&'static str>,
}

/// Compile-time method descriptor emitted by `#[messages]`.
pub struct MethodMeta {
    pub name: &'static str,
    pub mode: MethodMode,
    /// False when the macro inferred the conventional default from `&self`
    /// or `&mut self`. Mixed-lane actors require explicit mutation modes.
    pub explicit: bool,
}

/// Marker emitted only by `#[messages(agent)]`. `#[actor(agent)]` requires
/// this trait so the signed AgentActor entry cannot be built with unrestricted
/// service-style handler bodies.
#[doc(hidden)]
pub trait AgentMessageSet {
    /// True only when every mutating handler selected its lane explicitly.
    /// Mixed-lane actors use this to fail at compile time rather than waiting
    /// for package admission to reject an inferred mutation mode.
    const ALL_MUTATIONS_EXPLICIT: bool;
}

/// Typed message which may be emitted by a Linear handler after its Linear
/// state transition commits. The macro implements this only for handlers with
/// an explicit `#[msg(merge)]` contract, so a future runtime effect API can be
/// generic over a generated typed codec instead of accepting an unchecked
/// method name. Runtime admission must still validate the signed method mode.
pub trait AfterCommitMergeMessage<A> {
    const METHOD: &'static str;

    fn into_dynamic(self) -> crate::value::Msg;
}

/// Complete compile-time schema encoded into `.vos_agent`.
pub struct SchemaMeta {
    /// Must equal whether the storage slice passed to
    /// [`encode_with_storage`] is non-empty. Retained as an explicit
    /// generation-time assertion so a caller cannot accidentally omit storage
    /// descriptors while claiming a storage-capable actor.
    pub uses_storage: bool,
    /// Inline, constant, and skipped fields only. Row-backed fields belong in
    /// [`StorageFieldMeta`].
    pub fields: &'static [FieldMeta],
    pub methods: &'static [MethodMeta],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedField {
    pub name: String,
    pub codec: String,
    pub persistence: FieldPersistence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedStorageField {
    pub name: String,
    pub type_identity: String,
    pub lane: StateLane,
    pub prefix: Vec<u8>,
    pub committed: bool,
    pub leaf_domain: Option<String>,
    pub node_domain: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMethod {
    pub name: String,
    pub mode: MethodMode,
    pub explicit: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedSchema {
    pub entry: ExecutionEntryKind,
    pub uses_storage: bool,
    pub fields: Vec<ParsedField>,
    pub storage: Vec<ParsedStorageField>,
    pub methods: Vec<ParsedMethod>,
}

impl ParsedSchema {
    pub fn lanes(&self) -> LaneSet {
        let mut lanes = LaneSet::NONE;
        for field in &self.fields {
            if let FieldPersistence::State(lane) = field.persistence {
                lanes = lanes.union(LaneSet::of(lane));
            }
        }
        for field in &self.storage {
            lanes = lanes.union(LaneSet::of(field.lane));
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

    pub fn requirements(&self, proofs: bool) -> RuntimeRequirements {
        RuntimeRequirements {
            lanes: self.lanes(),
            scheduling: false,
            proofs,
        }
    }

    /// Identity of the declaration-ordered durable field layout. Method
    /// additions and policy changes may evolve independently, but a package-
    /// only actor upgrade must preserve this value until an explicit state
    /// migration protocol exists.
    pub fn state_layout_hash(&self) -> Hash {
        let mut bytes = Vec::new();
        let mut encoder = Encoder(&mut bytes);
        encoder.u16(self.fields.len() as u16);
        for field in &self.fields {
            encoder.string(&field.name);
            encoder.string(&field.codec);
            encoder.u8(encode_persistence(field.persistence));
        }
        encoder.u16(self.storage.len() as u16);
        for field in &self.storage {
            encoder.string(&field.name);
            encoder.string(&field.type_identity);
            encoder.u8(encode_lane(field.lane));
            encoder.bytes(&field.prefix);
            encoder.bool(field.committed);
            encoder.option(&field.leaf_domain, |encoder, domain| {
                encoder.string(domain);
            });
            encoder.option(&field.node_domain, |encoder, domain| {
                encoder.string(domain);
            });
        }
        Hash::digest(b"vos/agent/state-layout", &[&bytes])
    }

    pub fn validate(&self) -> bool {
        if self.uses_storage != !self.storage.is_empty()
            || self.fields.len() > MAX_FIELDS
            || self.storage.len() > MAX_FIELDS
            || self.fields.len().saturating_add(self.storage.len()) > MAX_FIELDS
            || self.methods.is_empty()
            || self.methods.len() > MAX_METHODS
            || self.fields.iter().any(|field| field.name.is_empty())
            || self.storage.iter().any(|field| !valid_storage_field(field))
            || self.methods.iter().any(|method| method.name.is_empty())
            || self.fields.iter().any(|field| {
                field.name.len() > MAX_NAME_BYTES
                    || field.codec.is_empty()
                    || field.codec.len() > MAX_CODEC_BYTES
            })
            || self
                .methods
                .iter()
                .any(|method| method.name.len() > MAX_NAME_BYTES)
            || has_duplicate_names(
                self.fields
                    .iter()
                    .map(|field| field.name.as_str())
                    .chain(self.storage.iter().map(|field| field.name.as_str())),
            )
            || has_duplicate_names(self.methods.iter().map(|method| method.name.as_str()))
            || has_overlapping_storage_prefixes(&self.storage)
        {
            return false;
        }

        let field_lanes = self.fields.iter().fold(LaneSet::NONE, |lanes, field| {
            if let FieldPersistence::State(lane) = field.persistence {
                lanes.union(LaneSet::of(lane))
            } else {
                lanes
            }
        });
        let field_lanes = self.storage.iter().fold(field_lanes, |lanes, field| {
            lanes.union(LaneSet::of(field.lane))
        });
        let mixed = field_lanes.bits().count_ones() > 1;
        !mixed
            || self.methods.iter().all(|method| {
                method.explicit
                    || matches!(
                        method.mode,
                        MethodMode::Query | MethodMode::LinearizableQuery | MethodMode::LocalQuery
                    )
            })
    }

    pub fn method(&self, name: &str) -> Option<&ParsedMethod> {
        self.methods.iter().find(|method| method.name == name)
    }
}

fn valid_storage_field(field: &ParsedStorageField) -> bool {
    if field.name.is_empty()
        || field.name.len() > MAX_NAME_BYTES
        || field.type_identity.is_empty()
        || field.type_identity.len() > MAX_TYPE_IDENTITY_BYTES
        || !valid_storage_prefix(&field.prefix)
    {
        return false;
    }

    match (&field.leaf_domain, &field.node_domain) {
        (None, None) => true,
        (Some(leaf), Some(node)) => {
            field.committed
                && !leaf.is_empty()
                && leaf.len() <= MAX_STORAGE_DOMAIN_BYTES
                && !node.is_empty()
                && node.len() <= MAX_STORAGE_DOMAIN_BYTES
                && leaf != node
        }
        _ => false,
    }
}

fn valid_storage_prefix(prefix: &[u8]) -> bool {
    !prefix.is_empty()
        && prefix.len() <= MAX_STORAGE_PREFIX_BYTES
        && prefix[0] != 0
        && !prefix.starts_with(b"__vos_")
}

fn has_overlapping_storage_prefixes(fields: &[ParsedStorageField]) -> bool {
    for (index, field) in fields.iter().enumerate() {
        if fields[index + 1..].iter().any(|other| {
            field.prefix.starts_with(&other.prefix) || other.prefix.starts_with(&field.prefix)
        }) {
            return true;
        }
    }
    false
}

fn has_duplicate_names<'a>(mut names: impl Iterator<Item = &'a str>) -> bool {
    let mut seen: Vec<&str> = Vec::new();
    names.any(|name| {
        if seen.contains(&name) {
            true
        } else {
            seen.push(name);
            false
        }
    })
}

/// Const encoder for standard-agent actor schemas. The caller owns the fixed
/// buffer so schema generation remains allocation-free in guest builds.
/// Service actors and Tasks use [`encode_with_entry`] explicitly.
pub const fn encode<const N: usize>(schema: &SchemaMeta) -> ([u8; N], usize) {
    encode_with_entry::<N>(schema, ExecutionEntryKind::AgentActor)
}

/// Encode a schema together with the program entry ABI. The actor macro uses
/// this form so Task binaries cannot be relabelled as ordinary actor packages.
pub const fn encode_with_entry<const N: usize>(
    schema: &SchemaMeta,
    entry: ExecutionEntryKind,
) -> ([u8; N], usize) {
    encode_with_storage::<N>(schema, &[], entry)
}

/// Encode an actor schema with explicit row-backed storage descriptors.
///
/// `schema.uses_storage` is checked against `storage` rather than encoded as a
/// second source of truth. The wire derives storage use from the descriptor
/// count, so it is impossible to sign an opaque "uses storage" bit without
/// also signing the exact keyspaces and commitment policy.
pub const fn encode_with_storage<const N: usize>(
    schema: &SchemaMeta,
    storage: &[StorageFieldMeta],
    entry: ExecutionEntryKind,
) -> ([u8; N], usize) {
    assert!(schema.uses_storage == !storage.is_empty());
    assert!(schema.fields.len() <= MAX_FIELDS);
    assert!(storage.len() <= MAX_FIELDS);
    assert!(schema.fields.len() + storage.len() <= MAX_FIELDS);
    assert!(schema.methods.len() <= MAX_METHODS);

    let mut output = [0u8; N];
    let mut position = 0usize;
    output[0] = MAGIC[0];
    output[1] = MAGIC[1];
    output[2] = MAGIC[2];
    output[3] = MAGIC[3];
    position += 4;
    output[position] = entry as u8;
    position += 1;

    let field_count = schema.fields.len() as u16;
    let field_count = field_count.to_le_bytes();
    output[position] = field_count[0];
    output[position + 1] = field_count[1];
    position += 2;
    let mut field_index = 0usize;
    while field_index < schema.fields.len() {
        position = write_str(&mut output, position, schema.fields[field_index].name);
        position = write_str(&mut output, position, schema.fields[field_index].codec);
        output[position] = encode_persistence(schema.fields[field_index].persistence);
        position += 1;
        field_index += 1;
    }

    let storage_count = storage.len() as u16;
    let storage_count = storage_count.to_le_bytes();
    output[position] = storage_count[0];
    output[position + 1] = storage_count[1];
    position += 2;
    let mut storage_index = 0usize;
    while storage_index < storage.len() {
        let field = &storage[storage_index];
        position = write_str(&mut output, position, field.name);
        position = write_str(&mut output, position, field.type_identity);
        output[position] = encode_lane(field.lane);
        position += 1;
        position = write_bytes(&mut output, position, field.prefix);
        output[position] = field.committed as u8;
        position += 1;
        match (field.leaf_domain, field.node_domain) {
            (Some(leaf), Some(node)) => {
                output[position] = 1;
                position += 1;
                position = write_str(&mut output, position, leaf);
                position = write_str(&mut output, position, node);
            }
            (None, None) => {
                output[position] = 0;
                position += 1;
            }
            _ => panic!("storage SMT domains must be declared together"),
        }
        storage_index += 1;
    }

    let method_count = schema.methods.len() as u16;
    let method_count = method_count.to_le_bytes();
    output[position] = method_count[0];
    output[position + 1] = method_count[1];
    position += 2;
    let mut method_index = 0usize;
    while method_index < schema.methods.len() {
        position = write_str(&mut output, position, schema.methods[method_index].name);
        output[position] = encode_mode(schema.methods[method_index].mode);
        output[position + 1] = schema.methods[method_index].explicit as u8;
        position += 2;
        method_index += 1;
    }
    (output, position)
}

const fn write_str<const N: usize>(output: &mut [u8; N], position: usize, value: &str) -> usize {
    write_bytes(output, position, value.as_bytes())
}

const fn write_bytes<const N: usize>(
    output: &mut [u8; N],
    mut position: usize,
    bytes: &[u8],
) -> usize {
    let len = (bytes.len() as u16).to_le_bytes();
    output[position] = len[0];
    output[position + 1] = len[1];
    position += 2;
    let mut index = 0usize;
    while index < bytes.len() {
        output[position + index] = bytes[index];
        index += 1;
    }
    position + bytes.len()
}

const fn encode_persistence(persistence: FieldPersistence) -> u8 {
    match persistence {
        FieldPersistence::State(StateLane::Linear) => 0,
        FieldPersistence::State(StateLane::Merge) => 1,
        FieldPersistence::State(StateLane::Local) => 2,
        FieldPersistence::Constant => 3,
        FieldPersistence::Skipped => 4,
    }
}

const fn encode_lane(lane: StateLane) -> u8 {
    match lane {
        StateLane::Linear => 0,
        StateLane::Merge => 1,
        StateLane::Local => 2,
    }
}

const fn encode_mode(mode: MethodMode) -> u8 {
    match mode {
        MethodMode::Query => 0,
        MethodMode::LinearizableQuery => 1,
        MethodMode::LocalQuery => 2,
        MethodMode::Linear => 3,
        MethodMode::Merge => 4,
        MethodMode::Local => 5,
    }
}

pub fn decode(input: &[u8]) -> Option<ParsedSchema> {
    if input.len() > MAX_ENCODED_BYTES || input.get(..4)? != MAGIC {
        return None;
    }
    let mut position = 4usize;
    let entry = match *input.get(position)? {
        0 => ExecutionEntryKind::ServiceActor,
        1 => ExecutionEntryKind::Task,
        2 => ExecutionEntryKind::AgentActor,
        _ => return None,
    };
    position += 1;
    let field_count = read_u16(input, &mut position)? as usize;
    if field_count > MAX_FIELDS {
        return None;
    }
    let mut fields = Vec::with_capacity(field_count);
    for _ in 0..field_count {
        fields.push(ParsedField {
            name: read_str(input, &mut position, MAX_NAME_BYTES)?,
            codec: read_str(input, &mut position, MAX_CODEC_BYTES)?,
            persistence: decode_persistence(*input.get(position)?)?,
        });
        position += 1;
    }
    let storage_count = read_u16(input, &mut position)? as usize;
    if storage_count > MAX_FIELDS || field_count.saturating_add(storage_count) > MAX_FIELDS {
        return None;
    }
    let mut storage = Vec::with_capacity(storage_count);
    for _ in 0..storage_count {
        let name = read_str(input, &mut position, MAX_NAME_BYTES)?;
        let type_identity = read_str(input, &mut position, MAX_TYPE_IDENTITY_BYTES)?;
        let lane = decode_lane(*input.get(position)?)?;
        position += 1;
        let prefix = read_bytes(input, &mut position, MAX_STORAGE_PREFIX_BYTES)?;
        let committed = read_bool(input, &mut position)?;
        let domains = read_bool(input, &mut position)?;
        let (leaf_domain, node_domain) = if domains {
            (
                Some(read_str(input, &mut position, MAX_STORAGE_DOMAIN_BYTES)?),
                Some(read_str(input, &mut position, MAX_STORAGE_DOMAIN_BYTES)?),
            )
        } else {
            (None, None)
        };
        storage.push(ParsedStorageField {
            name,
            type_identity,
            lane,
            prefix,
            committed,
            leaf_domain,
            node_domain,
        });
    }
    let method_count = read_u16(input, &mut position)? as usize;
    if method_count > MAX_METHODS {
        return None;
    }
    let mut methods = Vec::with_capacity(method_count);
    for _ in 0..method_count {
        let name = read_str(input, &mut position, MAX_NAME_BYTES)?;
        let mode = decode_mode(*input.get(position)?)?;
        let explicit = match *input.get(position + 1)? {
            0 => false,
            1 => true,
            _ => return None,
        };
        position += 2;
        methods.push(ParsedMethod {
            name,
            mode,
            explicit,
        });
    }
    let schema = ParsedSchema {
        entry,
        uses_storage: !storage.is_empty(),
        fields,
        storage,
        methods,
    };
    (position == input.len() && schema.validate()).then_some(schema)
}

pub fn raw_section_from_elf(elf: &[u8]) -> Option<Vec<u8>> {
    crate::metadata::raw_named_section_from_elf(elf, b".vos_agent")
}

pub fn from_elf(elf: &[u8]) -> Option<ParsedSchema> {
    decode(&raw_section_from_elf(elf)?)
}

fn read_u16(input: &[u8], position: &mut usize) -> Option<u16> {
    let value = u16::from_le_bytes(input.get(*position..*position + 2)?.try_into().ok()?);
    *position += 2;
    Some(value)
}

fn read_bytes(input: &[u8], position: &mut usize, maximum: usize) -> Option<Vec<u8>> {
    let len = read_u16(input, position)? as usize;
    if len > maximum {
        return None;
    }
    let bytes = input.get(*position..*position + len)?;
    *position += len;
    Some(bytes.to_vec())
}

fn read_str(input: &[u8], position: &mut usize, maximum: usize) -> Option<String> {
    String::from_utf8(read_bytes(input, position, maximum)?).ok()
}

fn read_bool(input: &[u8], position: &mut usize) -> Option<bool> {
    let value = match *input.get(*position)? {
        0 => false,
        1 => true,
        _ => return None,
    };
    *position += 1;
    Some(value)
}

const fn decode_persistence(value: u8) -> Option<FieldPersistence> {
    match value {
        0 => Some(FieldPersistence::State(StateLane::Linear)),
        1 => Some(FieldPersistence::State(StateLane::Merge)),
        2 => Some(FieldPersistence::State(StateLane::Local)),
        3 => Some(FieldPersistence::Constant),
        4 => Some(FieldPersistence::Skipped),
        _ => None,
    }
}

const fn decode_lane(value: u8) -> Option<StateLane> {
    match value {
        0 => Some(StateLane::Linear),
        1 => Some(StateLane::Merge),
        2 => Some(StateLane::Local),
        _ => None,
    }
}

const fn decode_mode(value: u8) -> Option<MethodMode> {
    match value {
        0 => Some(MethodMode::Query),
        1 => Some(MethodMode::LinearizableQuery),
        2 => Some(MethodMode::LocalQuery),
        3 => Some(MethodMode::Linear),
        4 => Some(MethodMode::Merge),
        5 => Some(MethodMode::Local),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: SchemaMeta = SchemaMeta {
        uses_storage: false,
        fields: &[
            FieldMeta {
                name: "title",
                codec: "String",
                persistence: FieldPersistence::State(StateLane::Linear),
            },
            FieldMeta {
                name: "edits",
                codec: "crdt::Counter",
                persistence: FieldPersistence::State(StateLane::Merge),
            },
        ],
        methods: &[
            MethodMeta {
                name: "rename",
                mode: MethodMode::Linear,
                explicit: true,
            },
            MethodMeta {
                name: "count_edit",
                mode: MethodMode::Merge,
                explicit: true,
            },
        ],
    };

    const STORAGE_SCHEMA: SchemaMeta = SchemaMeta {
        uses_storage: true,
        fields: SCHEMA.fields,
        methods: SCHEMA.methods,
    };

    const STORAGE_FIELDS: &[StorageFieldMeta] = &[StorageFieldMeta {
        name: "rows",
        type_identity: "example::StorageMap<u64,u64>",
        lane: StateLane::Merge,
        prefix: b"rows/",
        committed: true,
        leaf_domain: Some("example/smt/leaf/v1"),
        node_domain: Some("example/smt/node/v1"),
    }];

    fn storage_bytes(storage: &[StorageFieldMeta]) -> Vec<u8> {
        let (bytes, len) =
            encode_with_storage::<2048>(&STORAGE_SCHEMA, storage, ExecutionEntryKind::AgentActor);
        bytes[..len].to_vec()
    }

    fn first_storage_lane_offset(input: &[u8]) -> usize {
        let mut position = 5;
        let fields = read_u16(input, &mut position).unwrap();
        for _ in 0..fields {
            read_str(input, &mut position, MAX_NAME_BYTES).unwrap();
            read_str(input, &mut position, MAX_CODEC_BYTES).unwrap();
            position += 1;
        }
        assert!(read_u16(input, &mut position).unwrap() > 0);
        read_str(input, &mut position, MAX_NAME_BYTES).unwrap();
        read_str(input, &mut position, MAX_TYPE_IDENTITY_BYTES).unwrap();
        position
    }

    fn first_storage_committed_offset(input: &[u8]) -> usize {
        let mut position = first_storage_lane_offset(input) + 1;
        read_bytes(input, &mut position, MAX_STORAGE_PREFIX_BYTES).unwrap();
        position
    }

    #[test]
    fn schema_roundtrips_and_derives_shared_lanes() {
        const ENCODED: ([u8; 512], usize) = encode::<512>(&SCHEMA);
        let parsed = decode(&ENCODED.0[..ENCODED.1]).unwrap();
        assert_eq!(parsed.fields.len(), 2);
        assert_eq!(parsed.methods.len(), 2);
        assert_eq!(
            parsed.lanes(),
            LaneSet::of(StateLane::Linear).union(LaneSet::of(StateLane::Merge))
        );
    }

    #[test]
    fn mixed_fields_require_explicit_mutation_modes() {
        let mut parsed = ParsedSchema {
            entry: ExecutionEntryKind::AgentActor,
            uses_storage: false,
            fields: vec![
                ParsedField {
                    name: "linear".into(),
                    codec: "u64".into(),
                    persistence: FieldPersistence::State(StateLane::Linear),
                },
                ParsedField {
                    name: "merge".into(),
                    codec: "crdt::Counter".into(),
                    persistence: FieldPersistence::State(StateLane::Merge),
                },
            ],
            storage: Vec::new(),
            methods: vec![ParsedMethod {
                name: "change".into(),
                mode: MethodMode::Linear,
                explicit: false,
            }],
        };
        assert!(!parsed.validate());
        parsed.methods[0].explicit = true;
        assert!(parsed.validate());

        parsed.methods[0] = ParsedMethod {
            name: "read".into(),
            mode: MethodMode::Query,
            explicit: false,
        };
        assert!(
            parsed.validate(),
            "an immutable shared query has one unambiguous lane view"
        );
    }

    #[test]
    fn all_execution_entries_are_signed_and_round_trip() {
        const SERVICE: ([u8; 512], usize) =
            encode_with_entry::<512>(&SCHEMA, ExecutionEntryKind::ServiceActor);
        const AGENT: ([u8; 512], usize) = encode::<512>(&SCHEMA);
        const TASK: ([u8; 512], usize) =
            encode_with_entry::<512>(&SCHEMA, ExecutionEntryKind::Task);
        assert_ne!(&SERVICE.0[..SERVICE.1], &AGENT.0[..AGENT.1]);
        assert_ne!(&SERVICE.0[..SERVICE.1], &TASK.0[..TASK.1]);
        assert_ne!(&AGENT.0[..AGENT.1], &TASK.0[..TASK.1]);
        assert_eq!(
            decode(&SERVICE.0[..SERVICE.1]).unwrap().entry,
            ExecutionEntryKind::ServiceActor
        );
        assert_eq!(
            decode(&AGENT.0[..AGENT.1]).unwrap().entry,
            ExecutionEntryKind::AgentActor
        );
        assert_eq!(
            decode(&TASK.0[..TASK.1]).unwrap().entry,
            ExecutionEntryKind::Task
        );
    }

    #[test]
    fn linearizable_query_requires_the_linear_lane() {
        let parsed = ParsedSchema {
            entry: ExecutionEntryKind::AgentActor,
            uses_storage: false,
            fields: Vec::new(),
            storage: Vec::new(),
            methods: vec![ParsedMethod {
                name: "read".into(),
                mode: MethodMode::LinearizableQuery,
                explicit: true,
            }],
        };
        assert_eq!(
            parsed.requirements(false).lanes,
            LaneSet::of(StateLane::Linear)
        );
    }

    #[test]
    fn local_query_requires_the_local_lane() {
        let parsed = ParsedSchema {
            entry: ExecutionEntryKind::AgentActor,
            uses_storage: false,
            fields: Vec::new(),
            storage: Vec::new(),
            methods: vec![ParsedMethod {
                name: "read".into(),
                mode: MethodMode::LocalQuery,
                explicit: true,
            }],
        };
        assert_eq!(
            parsed.requirements(false).lanes,
            LaneSet::of(StateLane::Local)
        );
    }

    #[test]
    fn mixed_local_and_shared_state_uses_mode_specific_read_contracts() {
        let local_field = ParsedField {
            name: "cache".into(),
            codec: "String".into(),
            persistence: FieldPersistence::State(StateLane::Local),
        };
        let parsed = ParsedSchema {
            entry: ExecutionEntryKind::AgentActor,
            uses_storage: false,
            fields: vec![
                local_field,
                ParsedField {
                    name: "shared".into(),
                    codec: "u64".into(),
                    persistence: FieldPersistence::State(StateLane::Linear),
                },
            ],
            storage: Vec::new(),
            methods: vec![
                ParsedMethod {
                    name: "cache".into(),
                    mode: MethodMode::Local,
                    explicit: true,
                },
                ParsedMethod {
                    name: "read".into(),
                    mode: MethodMode::Query,
                    explicit: false,
                },
            ],
        };
        assert!(parsed.validate());
        assert!(MethodMode::Local.can_read(StateLane::Linear));
        assert!(MethodMode::Local.can_read(StateLane::Local));
        assert!(MethodMode::Query.can_read(StateLane::Linear));
        assert!(!MethodMode::Query.can_read(StateLane::Local));
    }

    #[test]
    fn storage_use_is_signed_in_the_schema() {
        const PLAIN: ([u8; 512], usize) = encode::<512>(&SCHEMA);
        const WITH_STORAGE: ([u8; 512], usize) = encode_with_storage::<512>(
            &STORAGE_SCHEMA,
            STORAGE_FIELDS,
            ExecutionEntryKind::AgentActor,
        );
        assert_ne!(&PLAIN.0[..PLAIN.1], &WITH_STORAGE.0[..WITH_STORAGE.1]);
        let plain = decode(&PLAIN.0[..PLAIN.1]).expect("plain schema");
        let storage = decode(&WITH_STORAGE.0[..WITH_STORAGE.1]).expect("storage schema");
        assert!(storage.uses_storage);
        assert_eq!(storage.storage.len(), 1);
        assert_eq!(storage.storage[0].prefix, b"rows/");
        assert_eq!(storage.storage[0].lane, StateLane::Merge);
        assert_eq!(
            storage.storage[0].leaf_domain.as_deref(),
            STORAGE_FIELDS[0].leaf_domain
        );
        assert_ne!(plain.state_layout_hash(), storage.state_layout_hash());
    }

    #[test]
    fn storage_prefixes_are_unique_and_prefix_free() {
        const OVERLAPPING: &[StorageFieldMeta] = &[
            StorageFieldMeta {
                name: "rows",
                type_identity: "example::StorageMap<u64,u64>",
                lane: StateLane::Linear,
                prefix: b"rows/",
                committed: false,
                leaf_domain: None,
                node_domain: None,
            },
            StorageFieldMeta {
                name: "private_rows",
                type_identity: "example::StorageMap<u64,u64>",
                lane: StateLane::Linear,
                prefix: b"rows/private/",
                committed: false,
                leaf_domain: None,
                node_domain: None,
            },
        ];
        assert!(decode(&storage_bytes(OVERLAPPING)).is_none());

        const DUPLICATE_PREFIX: &[StorageFieldMeta] = &[
            StorageFieldMeta {
                name: "rows",
                type_identity: "example::StorageMap<u64,u64>",
                lane: StateLane::Linear,
                prefix: b"rows/",
                committed: false,
                leaf_domain: None,
                node_domain: None,
            },
            StorageFieldMeta {
                name: "other_rows",
                type_identity: "example::StorageSet<u64>",
                lane: StateLane::Merge,
                prefix: b"rows/",
                committed: false,
                leaf_domain: None,
                node_domain: None,
            },
        ];
        assert!(decode(&storage_bytes(DUPLICATE_PREFIX)).is_none());

        const DUPLICATE_NAME: &[StorageFieldMeta] = &[StorageFieldMeta {
            name: "title",
            type_identity: "example::StorageValue<String>",
            lane: StateLane::Linear,
            prefix: b"stored-title/",
            committed: false,
            leaf_domain: None,
            node_domain: None,
        }];
        assert!(
            decode(&storage_bytes(DUPLICATE_NAME)).is_none(),
            "inline and row-backed field names share one namespace"
        );
    }

    #[test]
    fn storage_lane_and_boolean_tags_are_strict() {
        let original = storage_bytes(STORAGE_FIELDS);

        let mut bad_lane = original.clone();
        bad_lane[first_storage_lane_offset(&original)] = 3;
        assert!(decode(&bad_lane).is_none());

        let committed = first_storage_committed_offset(&original);
        let mut bad_committed = original.clone();
        bad_committed[committed] = 2;
        assert!(decode(&bad_committed).is_none());

        let mut bad_domains = original;
        bad_domains[committed + 1] = 2;
        assert!(decode(&bad_domains).is_none());
    }

    #[test]
    fn storage_prefix_and_domain_bounds_are_strict() {
        const PREFIX_129: &[u8] =
            b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        const DOMAIN_129: &str = concat!(
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "x",
        );
        const BAD_PREFIX: &[StorageFieldMeta] = &[StorageFieldMeta {
            name: "rows",
            type_identity: "example::StorageMap<u64,u64>",
            lane: StateLane::Linear,
            prefix: PREFIX_129,
            committed: false,
            leaf_domain: None,
            node_domain: None,
        }];
        const BAD_DOMAIN: &[StorageFieldMeta] = &[StorageFieldMeta {
            name: "rows",
            type_identity: "example::StorageMap<u64,u64>",
            lane: StateLane::Linear,
            prefix: b"rows/",
            committed: true,
            leaf_domain: Some(DOMAIN_129),
            node_domain: Some("example/smt/node/v1"),
        }];
        const EMPTY_DOMAIN: &[StorageFieldMeta] = &[StorageFieldMeta {
            name: "rows",
            type_identity: "example::StorageMap<u64,u64>",
            lane: StateLane::Linear,
            prefix: b"rows/",
            committed: true,
            leaf_domain: Some(""),
            node_domain: Some("example/smt/node/v1"),
        }];
        const UNCOMMITTED_DOMAINS: &[StorageFieldMeta] = &[StorageFieldMeta {
            name: "rows",
            type_identity: "example::StorageMap<u64,u64>",
            lane: StateLane::Linear,
            prefix: b"rows/",
            committed: false,
            leaf_domain: Some("example/smt/leaf/v1"),
            node_domain: Some("example/smt/node/v1"),
        }];
        const COLLIDING_DOMAINS: &[StorageFieldMeta] = &[StorageFieldMeta {
            name: "rows",
            type_identity: "example::StorageMap<u64,u64>",
            lane: StateLane::Linear,
            prefix: b"rows/",
            committed: true,
            leaf_domain: Some("example/smt/v1"),
            node_domain: Some("example/smt/v1"),
        }];

        assert_eq!(PREFIX_129.len(), MAX_STORAGE_PREFIX_BYTES + 1);
        assert_eq!(DOMAIN_129.len(), MAX_STORAGE_DOMAIN_BYTES + 1);
        assert!(decode(&storage_bytes(BAD_PREFIX)).is_none());
        assert!(decode(&storage_bytes(BAD_DOMAIN)).is_none());
        assert!(decode(&storage_bytes(EMPTY_DOMAIN)).is_none());
        assert!(decode(&storage_bytes(UNCOMMITTED_DOMAINS)).is_none());
        assert!(decode(&storage_bytes(COLLIDING_DOMAINS)).is_none());
    }

    #[test]
    fn storage_schema_rejects_reserved_and_noncanonical_prefixes() {
        const PREFIXES: &[&[u8]] = &[b"", b"\0private/", b"__vos_private/"];
        for prefix in PREFIXES {
            let fields = [StorageFieldMeta {
                name: "rows",
                type_identity: "example::StorageMap<u64,u64>",
                lane: StateLane::Linear,
                prefix,
                committed: false,
                leaf_domain: None,
                node_domain: None,
            }];
            assert!(decode(&storage_bytes(&fields)).is_none());
        }
    }

    #[test]
    fn storage_schema_rejects_trailing_and_oversized_input() {
        let mut trailing = storage_bytes(STORAGE_FIELDS);
        trailing.push(0);
        assert!(decode(&trailing).is_none());

        let mut oversized = storage_bytes(STORAGE_FIELDS);
        oversized.resize(MAX_ENCODED_BYTES + 1, 0);
        assert!(decode(&oversized).is_none());
    }

    #[test]
    #[should_panic]
    fn encoder_rejects_an_opaque_storage_claim() {
        let _ = encode_with_storage::<512>(&STORAGE_SCHEMA, &[], ExecutionEntryKind::AgentActor);
    }
}
