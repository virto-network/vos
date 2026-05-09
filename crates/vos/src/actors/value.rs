//! Dynamic value types for cross-actor communication.
//!
//! `Value` is the universal data type for dynamic messaging between actors.
//! Used for constructor init args, cross-actor calls, and handler replies.
//!
//! Only simple, flat types are supported — no nested structs. This keeps
//! the encoding compact and avoids coupling between actor implementations.

use alloc::{string::String, vec::Vec};

/// Error returned when an `ask()` invocation fails.
#[derive(Debug, Clone, PartialEq)]
pub enum InvokeError {
    /// The target actor panicked.
    Panicked,
    /// The target service was not found.
    NotFound,
    /// The target ran out of gas.
    OutOfGas,
    /// Unknown error status byte from the wire.
    Unknown(u8),
}

impl core::fmt::Display for InvokeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InvokeError::Panicked => write!(f, "invoke: child panicked"),
            InvokeError::NotFound => write!(f, "invoke: service not found"),
            InvokeError::OutOfGas => write!(f, "invoke: out of gas"),
            InvokeError::Unknown(s) => write!(f, "invoke: unknown error (0x{s:02x})"),
        }
    }
}

/// A dynamically-typed value.
///
/// Flat by design — no recursive nesting. Covers the types expressible
/// in TOML manifests and useful for cross-actor communication.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq)]
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
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            Value::U8(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_u16(&self) -> Option<u16> {
        match self {
            Value::U16(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Value::U32(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::U64(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Value::I32(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::I64(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_list_u32(&self) -> Option<&[u32]> {
        match self {
            Value::ListU32(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_list_str(&self) -> Option<&[String]> {
        match self {
            Value::ListStr(v) => Some(v),
            _ => None,
        }
    }
}

// ── From impls for ergonomic construction ────────────────────────

impl From<()> for Value {
    fn from(_: ()) -> Self {
        Value::Unit
    }
}
impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Value::Bool(v)
    }
}
impl From<u8> for Value {
    fn from(v: u8) -> Self {
        Value::U8(v)
    }
}
impl From<u16> for Value {
    fn from(v: u16) -> Self {
        Value::U16(v)
    }
}
impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Value::U32(v)
    }
}
impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Value::U64(v)
    }
}
impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::I32(v)
    }
}
impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::I64(v)
    }
}
impl From<String> for Value {
    fn from(v: String) -> Self {
        Value::Str(v)
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Value::Str(String::from(v))
    }
}
impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Value::Bytes(v)
    }
}
impl From<Vec<u32>> for Value {
    fn from(v: Vec<u32>) -> Self {
        Value::ListU32(v)
    }
}
impl From<Vec<String>> for Value {
    fn from(v: Vec<String>) -> Self {
        Value::ListStr(v)
    }
}

// ── Args ─────────────────────────────────────────────────────────

/// A named collection of values — used for message arguments and init args.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
#[rkyv(crate = rkyv)]
pub struct Args(pub Vec<(String, Value)>);

impl Default for Args {
    fn default() -> Self {
        Args::new()
    }
}

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

    pub fn get_u8(&self, key: &str) -> Option<u8> {
        self.get(key)?.as_u8()
    }
    pub fn get_u16(&self, key: &str) -> Option<u16> {
        self.get(key)?.as_u16()
    }
    pub fn get_u32(&self, key: &str) -> Option<u32> {
        self.get(key)?.as_u32()
    }
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key)?.as_u64()
    }
    pub fn get_i32(&self, key: &str) -> Option<i32> {
        self.get(key)?.as_i32()
    }
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key)?.as_i64()
    }
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key)?.as_bool()
    }
    pub fn get_str(&self, key: &str) -> Option<String> {
        self.get(key)?.as_str().map(String::from)
    }
    pub fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.get(key)?.as_bytes().map(Vec::from)
    }
    pub fn get_list_u32(&self, key: &str) -> Option<Vec<u32>> {
        self.get(key)?.as_list_u32().map(Vec::from)
    }
    pub fn get_list_str(&self, key: &str) -> Option<Vec<String>> {
        self.get(key)?.as_list_str().map(Vec::from)
    }
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
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
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

// ── JS-friendly description codec ────────────────────────────────────
//
// Lets non-Rust hosts (JS, etc.) build Msg/Value without implementing
// rkyv. The wire format is a simple tagged binary that maps 1:1 to
// the `Value` enum variants.
//
// Format (all integers little-endian):
//   ValueDesc:
//     [tag:u8][payload]
//     tag values:
//       0  Unit       (no payload)
//       1  Bool       [u8]
//       2  U8         [u8]
//       3  U16        [u16]
//       4  U32        [u32]
//       5  U64        [u64]
//       6  I32        [i32]
//       7  I64        [i64]
//       8  Str        [u32 len][utf-8 bytes]
//       9  Bytes      [u32 len][bytes]
//       10 ListU32    [u32 count][count * u32]
//       11 ListStr    [u32 count][for each: u32 len + utf-8 bytes]
//
//   MsgDesc:
//     [name_len:u32][utf-8 bytes]
//     [arg_count:u32]
//       [arg_name_len:u32][utf-8 bytes]
//       <ValueDesc>

pub mod desc {
    use super::{Args, Msg, Value};
    use alloc::string::String;
    use alloc::vec::Vec;

    pub const TAG_UNIT: u8 = 0;
    pub const TAG_BOOL: u8 = 1;
    pub const TAG_U8: u8 = 2;
    pub const TAG_U16: u8 = 3;
    pub const TAG_U32: u8 = 4;
    pub const TAG_U64: u8 = 5;
    pub const TAG_I32: u8 = 6;
    pub const TAG_I64: u8 = 7;
    pub const TAG_STR: u8 = 8;
    pub const TAG_BYTES: u8 = 9;
    pub const TAG_LIST_U32: u8 = 10;
    pub const TAG_LIST_STR: u8 = 11;

    /// Decode a `MsgDesc` blob into a typed `Msg`.
    /// Returns `None` on truncation or invalid tags.
    pub fn decode_msg(bytes: &[u8]) -> Option<Msg> {
        let mut c = Cursor::new(bytes);
        let name = c.read_str()?;
        let args = read_args(&mut c)?;
        Some(Msg { name, args })
    }

    /// Decode an `ArgsDesc` blob (the args portion alone, no name).
    /// Used for actor init args from non-Rust hosts.
    pub fn decode_args(bytes: &[u8]) -> Option<Args> {
        let mut c = Cursor::new(bytes);
        read_args(&mut c)
    }

    fn read_args(c: &mut Cursor<'_>) -> Option<Args> {
        let arg_count = c.read_u32()? as usize;
        let mut args = Args::new();
        for _ in 0..arg_count {
            let key = c.read_str()?;
            let value = c.read_value()?;
            args = args.with(key, value);
        }
        Some(args)
    }

    /// Encode a `Value` into the description format.
    pub fn encode_value(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        write_value(&mut out, value);
        out
    }

    /// Decode a `ValueDesc` blob into a typed `Value`.
    pub fn decode_value(bytes: &[u8]) -> Option<Value> {
        let mut c = Cursor::new(bytes);
        c.read_value()
    }

    fn write_value(out: &mut Vec<u8>, value: &Value) {
        match value {
            Value::Unit => out.push(TAG_UNIT),
            Value::Bool(b) => {
                out.push(TAG_BOOL);
                out.push(if *b { 1 } else { 0 });
            }
            Value::U8(v) => {
                out.push(TAG_U8);
                out.push(*v);
            }
            Value::U16(v) => {
                out.push(TAG_U16);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Value::U32(v) => {
                out.push(TAG_U32);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Value::U64(v) => {
                out.push(TAG_U64);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Value::I32(v) => {
                out.push(TAG_I32);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Value::I64(v) => {
                out.push(TAG_I64);
                out.extend_from_slice(&v.to_le_bytes());
            }
            Value::Str(s) => {
                out.push(TAG_STR);
                let b = s.as_bytes();
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
            Value::Bytes(b) => {
                out.push(TAG_BYTES);
                out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                out.extend_from_slice(b);
            }
            Value::ListU32(items) => {
                out.push(TAG_LIST_U32);
                out.extend_from_slice(&(items.len() as u32).to_le_bytes());
                for v in items {
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
            Value::ListStr(items) => {
                out.push(TAG_LIST_STR);
                out.extend_from_slice(&(items.len() as u32).to_le_bytes());
                for s in items {
                    let b = s.as_bytes();
                    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                    out.extend_from_slice(b);
                }
            }
        }
    }

    struct Cursor<'a> {
        buf: &'a [u8],
        pos: usize,
    }
    impl<'a> Cursor<'a> {
        fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.pos + n > self.buf.len() {
                return None;
            }
            let s = &self.buf[self.pos..self.pos + n];
            self.pos += n;
            Some(s)
        }
        fn read_u8(&mut self) -> Option<u8> {
            self.take(1).map(|b| b[0])
        }
        fn read_u16(&mut self) -> Option<u16> {
            self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
        }
        fn read_u32(&mut self) -> Option<u32> {
            self.take(4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }
        fn read_u64(&mut self) -> Option<u64> {
            self.take(8)
                .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        }
        fn read_i32(&mut self) -> Option<i32> {
            self.read_u32().map(|v| v as i32)
        }
        fn read_i64(&mut self) -> Option<i64> {
            self.read_u64().map(|v| v as i64)
        }
        fn read_str(&mut self) -> Option<String> {
            let len = self.read_u32()? as usize;
            let b = self.take(len)?;
            core::str::from_utf8(b).ok().map(String::from)
        }
        fn read_value(&mut self) -> Option<Value> {
            match self.read_u8()? {
                TAG_UNIT => Some(Value::Unit),
                TAG_BOOL => Some(Value::Bool(self.read_u8()? != 0)),
                TAG_U8 => Some(Value::U8(self.read_u8()?)),
                TAG_U16 => Some(Value::U16(self.read_u16()?)),
                TAG_U32 => Some(Value::U32(self.read_u32()?)),
                TAG_U64 => Some(Value::U64(self.read_u64()?)),
                TAG_I32 => Some(Value::I32(self.read_i32()?)),
                TAG_I64 => Some(Value::I64(self.read_i64()?)),
                TAG_STR => Some(Value::Str(self.read_str()?)),
                TAG_BYTES => {
                    let len = self.read_u32()? as usize;
                    Some(Value::Bytes(self.take(len)?.to_vec()))
                }
                TAG_LIST_U32 => {
                    let count = self.read_u32()? as usize;
                    let mut items = Vec::with_capacity(count);
                    for _ in 0..count {
                        items.push(self.read_u32()?);
                    }
                    Some(Value::ListU32(items))
                }
                TAG_LIST_STR => {
                    let count = self.read_u32()? as usize;
                    let mut items = Vec::with_capacity(count);
                    for _ in 0..count {
                        items.push(self.read_str()?);
                    }
                    Some(Value::ListStr(items))
                }
                _ => None,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn roundtrip_value_str() {
            let v = Value::Str(String::from("hello"));
            let bytes = encode_value(&v);
            let decoded = decode_value(&bytes).unwrap();
            assert_eq!(v, decoded);
        }

        #[test]
        fn roundtrip_value_u32() {
            let v = Value::U32(42);
            let bytes = encode_value(&v);
            assert_eq!(decode_value(&bytes).unwrap(), v);
        }

        #[test]
        fn roundtrip_msg() {
            // Build a desc blob manually and decode
            let mut buf = Vec::new();
            buf.extend_from_slice(&5u32.to_le_bytes());
            buf.extend_from_slice(b"hello");
            buf.extend_from_slice(&1u32.to_le_bytes()); // 1 arg
            buf.extend_from_slice(&3u32.to_le_bytes());
            buf.extend_from_slice(b"key");
            buf.push(TAG_U32);
            buf.extend_from_slice(&7u32.to_le_bytes());

            let msg = decode_msg(&buf).unwrap();
            assert_eq!(msg.name, "hello");
            assert_eq!(msg.args.get_u32("key"), Some(7));
        }
    }
}
