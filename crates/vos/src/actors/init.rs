//! Typed init arguments for actor constructors.
//!
//! `InitArgs` is a self-describing map of named values that vosx (the host)
//! builds from the TOML manifest and writes to storage. The actor's generated
//! `__vos_create` reads and extracts typed fields by name.
//!
//! Only simple, TOML-expressible types are supported — no nested structs.

use alloc::{string::String, vec::Vec};

/// A single init argument value.
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Debug, Clone,
)]
#[rkyv(crate = rkyv)]
pub enum InitValue {
    U32(u32),
    U64(u64),
    I32(i32),
    Bool(bool),
    Str(String),
    Bytes(Vec<u8>),
    ListU32(Vec<u32>),
}

/// Named init arguments for an actor constructor.
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Debug, Clone,
)]
#[rkyv(crate = rkyv)]
pub struct InitArgs(pub Vec<(String, InitValue)>);

impl InitArgs {
    pub fn new() -> Self {
        InitArgs(Vec::new())
    }

    pub fn with(mut self, name: impl Into<String>, value: InitValue) -> Self {
        self.0.push((name.into(), value));
        self
    }

    pub fn get(&self, key: &str) -> Option<&InitValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn get_u32(&self, key: &str) -> Option<u32> {
        match self.get(key)? {
            InitValue::U32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        match self.get(key)? {
            InitValue::U64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_i32(&self, key: &str) -> Option<i32> {
        match self.get(key)? {
            InitValue::I32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.get(key)? {
            InitValue::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_str(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            InitValue::Str(v) => Some(v.clone()),
            _ => None,
        }
    }

    pub fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
        match self.get(key)? {
            InitValue::Bytes(v) => Some(v.clone()),
            _ => None,
        }
    }

    pub fn get_list_u32(&self, key: &str) -> Option<Vec<u32>> {
        match self.get(key)? {
            InitValue::ListU32(v) => Some(v.clone()),
            _ => None,
        }
    }
}
