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

pub const MAGIC: [u8; 4] = *b"AGSC";
pub const MAX_FIELDS: usize = 256;
pub const MAX_METHODS: usize = 256;
pub const MAX_ENCODED_BYTES: usize = 16 * 1024;
pub const MAX_NAME_BYTES: usize = 128;
pub const MAX_CODEC_BYTES: usize = 512;

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
    /// Whether the actor declares host-backed `#[storage]` fields. This is
    /// signed even though the standard runtime currently rejects such actors,
    /// so a future runtime cannot accidentally reinterpret an unsupported
    /// effect surface as ordinary lane state.
    pub uses_storage: bool,
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
        encoder.u8(self.uses_storage as u8);
        encoder.u16(self.fields.len() as u16);
        for field in &self.fields {
            encoder.string(&field.name);
            encoder.string(&field.codec);
            encoder.u8(encode_persistence(field.persistence));
        }
        Hash::digest(b"vos/agent/state-layout", &[&bytes])
    }

    pub fn validate(&self) -> bool {
        if self.fields.len() > MAX_FIELDS
            || self.methods.is_empty()
            || self.methods.len() > MAX_METHODS
            || self.fields.iter().any(|field| field.name.is_empty())
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
            || has_duplicate_names(self.fields.iter().map(|field| field.name.as_str()))
            || has_duplicate_names(self.methods.iter().map(|method| method.name.as_str()))
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
    let mut output = [0u8; N];
    let mut position = 0usize;
    output[0] = MAGIC[0];
    output[1] = MAGIC[1];
    output[2] = MAGIC[2];
    output[3] = MAGIC[3];
    position += 4;
    output[position] = entry as u8;
    position += 1;
    output[position] = schema.uses_storage as u8;
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

const fn write_str<const N: usize>(
    output: &mut [u8; N],
    mut position: usize,
    value: &str,
) -> usize {
    let bytes = value.as_bytes();
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
    let uses_storage = match *input.get(position)? {
        0 => false,
        1 => true,
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
            name: read_str(input, &mut position)?,
            codec: read_str(input, &mut position)?,
            persistence: decode_persistence(*input.get(position)?)?,
        });
        position += 1;
    }
    let method_count = read_u16(input, &mut position)? as usize;
    if method_count > MAX_METHODS {
        return None;
    }
    let mut methods = Vec::with_capacity(method_count);
    for _ in 0..method_count {
        let name = read_str(input, &mut position)?;
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
        uses_storage,
        fields,
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

fn read_str(input: &[u8], position: &mut usize) -> Option<String> {
    let len = read_u16(input, position)? as usize;
    let bytes = input.get(*position..*position + len)?;
    let value = core::str::from_utf8(bytes).ok()?.into();
    *position += len;
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
        const WITH_STORAGE_SCHEMA: SchemaMeta = SchemaMeta {
            uses_storage: true,
            fields: SCHEMA.fields,
            methods: SCHEMA.methods,
        };
        const WITH_STORAGE: ([u8; 512], usize) = encode::<512>(&WITH_STORAGE_SCHEMA);
        assert_ne!(&PLAIN.0[..PLAIN.1], &WITH_STORAGE.0[..WITH_STORAGE.1]);
        let plain = decode(&PLAIN.0[..PLAIN.1]).expect("plain schema");
        let storage = decode(&WITH_STORAGE.0[..WITH_STORAGE.1]).expect("storage schema");
        assert!(storage.uses_storage);
        assert_ne!(plain.state_layout_hash(), storage.state_layout_hash());
    }
}
