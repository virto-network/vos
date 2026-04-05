//! Dynamic value types for cross-actor communication.
//!
//! `Value` is the universal data type for dynamic messaging between actors.
//! Used for constructor init args, cross-actor calls, and handler replies.
//!
//! Only simple, flat types are supported — no nested structs. This keeps
//! the encoding compact and avoids coupling between actor implementations.

use alloc::{string::String, vec::Vec};

/// A dynamically-typed value.
///
/// Flat by design — no recursive nesting. Covers the types expressible
/// in TOML manifests and useful for cross-actor communication.
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Debug, Clone, PartialEq,
)]
#[rkyv(crate = rkyv)]
pub enum Value {
    Unit,
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    I32(i32),
    I64(i64),
    Str(String),
    Bytes(Vec<u8>),
    ListU32(Vec<u32>),
    ListStr(Vec<String>),
}

// ── Typed accessors ──────────────────────────────────────────────

impl Value {
    pub fn as_u8(&self) -> Option<u8> { match self { Value::U8(v) => Some(*v), _ => None } }
    pub fn as_u16(&self) -> Option<u16> { match self { Value::U16(v) => Some(*v), _ => None } }
    pub fn as_u32(&self) -> Option<u32> { match self { Value::U32(v) => Some(*v), _ => None } }
    pub fn as_u64(&self) -> Option<u64> { match self { Value::U64(v) => Some(*v), _ => None } }
    pub fn as_i32(&self) -> Option<i32> { match self { Value::I32(v) => Some(*v), _ => None } }
    pub fn as_i64(&self) -> Option<i64> { match self { Value::I64(v) => Some(*v), _ => None } }
    pub fn as_bool(&self) -> Option<bool> { match self { Value::Bool(v) => Some(*v), _ => None } }

    pub fn as_str(&self) -> Option<&str> {
        match self { Value::Str(v) => Some(v), _ => None }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self { Value::Bytes(v) => Some(v), _ => None }
    }
    pub fn as_list_u32(&self) -> Option<&[u32]> {
        match self { Value::ListU32(v) => Some(v), _ => None }
    }
    pub fn as_list_str(&self) -> Option<&[String]> {
        match self { Value::ListStr(v) => Some(v), _ => None }
    }
}

// ── From impls for ergonomic construction ────────────────────────

impl From<()> for Value { fn from(_: ()) -> Self { Value::Unit } }
impl From<bool> for Value { fn from(v: bool) -> Self { Value::Bool(v) } }
impl From<u8> for Value { fn from(v: u8) -> Self { Value::U8(v) } }
impl From<u16> for Value { fn from(v: u16) -> Self { Value::U16(v) } }
impl From<u32> for Value { fn from(v: u32) -> Self { Value::U32(v) } }
impl From<u64> for Value { fn from(v: u64) -> Self { Value::U64(v) } }
impl From<i32> for Value { fn from(v: i32) -> Self { Value::I32(v) } }
impl From<i64> for Value { fn from(v: i64) -> Self { Value::I64(v) } }
impl From<String> for Value { fn from(v: String) -> Self { Value::Str(v) } }
impl From<&str> for Value { fn from(v: &str) -> Self { Value::Str(String::from(v)) } }
impl From<Vec<u8>> for Value { fn from(v: Vec<u8>) -> Self { Value::Bytes(v) } }
impl From<Vec<u32>> for Value { fn from(v: Vec<u32>) -> Self { Value::ListU32(v) } }
impl From<Vec<String>> for Value { fn from(v: Vec<String>) -> Self { Value::ListStr(v) } }

// ── Args ─────────────────────────────────────────────────────────

/// A named collection of values — used for message arguments and init args.
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Debug, Clone,
)]
#[rkyv(crate = rkyv)]
pub struct Args(pub Vec<(String, Value)>);

impl Args {
    pub fn new() -> Self {
        Args(Vec::new())
    }

    pub fn with(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.0.push((name.into(), value.into()));
        self
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn get_u8(&self, key: &str) -> Option<u8> { self.get(key)?.as_u8() }
    pub fn get_u16(&self, key: &str) -> Option<u16> { self.get(key)?.as_u16() }
    pub fn get_u32(&self, key: &str) -> Option<u32> { self.get(key)?.as_u32() }
    pub fn get_u64(&self, key: &str) -> Option<u64> { self.get(key)?.as_u64() }
    pub fn get_i32(&self, key: &str) -> Option<i32> { self.get(key)?.as_i32() }
    pub fn get_i64(&self, key: &str) -> Option<i64> { self.get(key)?.as_i64() }
    pub fn get_bool(&self, key: &str) -> Option<bool> { self.get(key)?.as_bool() }
    pub fn get_str(&self, key: &str) -> Option<String> { self.get(key)?.as_str().map(String::from) }
    pub fn get_bytes(&self, key: &str) -> Option<Vec<u8>> { self.get(key)?.as_bytes().map(Vec::from) }
    pub fn get_list_u32(&self, key: &str) -> Option<Vec<u32>> { self.get(key)?.as_list_u32().map(Vec::from) }
    pub fn get_list_str(&self, key: &str) -> Option<Vec<String>> { self.get(key)?.as_list_str().map(Vec::from) }
}

// ── Msg ──────────────────────────────────────────────────────────

/// Tag byte prepended to dynamic `Msg` payloads so `dispatch_one` can
/// distinguish them from typed `{Name}Msg` rkyv bytes.
pub const TAG_DYNAMIC: u8 = 0xFF;

/// Trait for converting a dynamic `Msg` into a typed message enum.
/// Generated by `#[messages]` — each variant matches on `msg.name`
/// and extracts typed args.
pub trait FromDynamic: Sized {
    fn from_dynamic(msg: &Msg) -> Option<Self>;
}

/// A dynamic message: target message name + arguments.
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Debug, Clone,
)]
#[rkyv(crate = rkyv)]
pub struct Msg {
    pub name: String,
    pub args: Args,
}

impl Msg {
    pub fn new(name: impl Into<String>) -> Self {
        Msg {
            name: name.into(),
            args: Args::new(),
        }
    }

    pub fn with(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.args = self.args.with(name, value);
        self
    }
}
