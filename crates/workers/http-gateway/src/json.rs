//! JSON codec: top-level `{ "k": V, ... }` ⇄ `Vec<(String, vos::Value)>`,
//! and `vos::Value` → `serde_json::Value`.
//!
//! Parsing accepts a flat object whose values are scalars, strings,
//! null, or homogeneous arrays. Anything richer (nested objects,
//! mixed-type arrays, floats) is rejected — the URL contract is
//! "method name + flat argument map".
//!
//! Serialization renders the whole `vos::Value` enum. `Bytes` becomes
//! a base16 string — JSON isn't a blob transport, so we surface them
//! as inspectable text.

use vos::actors::value::Value;

use crate::types::IoResult;

pub(crate) fn parse_flat_json(body: &[u8]) -> IoResult<Vec<(String, Value)>> {
    let json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("{e}"))?;
    let serde_json::Value::Object(map) = json else {
        return Err("expected a top-level JSON object".into());
    };
    map.into_iter()
        .map(|(k, v)| Ok((k, json_to_value(v)?)))
        .collect()
}

pub(crate) fn value_to_json(v: &Value) -> Vec<u8> {
    serde_json::to_vec(&value_to_json_value(v)).unwrap_or_else(|_| b"null".to_vec())
}

fn json_to_value(j: serde_json::Value) -> IoResult<Value> {
    use serde_json::Value as J;
    Ok(match j {
        J::Null => Value::Unit,
        J::Bool(b) => Value::Bool(b),
        J::Number(n) => json_number_to_value(n)?,
        J::String(s) => Value::Str(s),
        J::Array(xs) => json_array_to_value(xs)?,
        J::Object(_) => return Err("nested objects are not supported".into()),
    })
}

fn json_number_to_value(n: serde_json::Number) -> IoResult<Value> {
    if let Some(u) = n.as_u64() {
        return Ok(if u <= u32::MAX as u64 { Value::U32(u as u32) } else { Value::U64(u) });
    }
    if let Some(i) = n.as_i64() {
        return Ok(Value::I64(i));
    }
    // `vos::Value` has no float variant — reject rather than silently
    // string-encode, which would surprise receivers expecting a number.
    Err(format!("non-integer number {n} unsupported"))
}

fn json_array_to_value(xs: Vec<serde_json::Value>) -> IoResult<Value> {
    if xs.is_empty() {
        return Ok(Value::ListStr(Vec::new()));
    }
    if xs.iter().all(serde_json::Value::is_string) {
        let strings = xs.into_iter()
            .map(|v| match v { serde_json::Value::String(s) => s, _ => unreachable!() })
            .collect();
        return Ok(Value::ListStr(strings));
    }
    if xs.iter().all(|v| v.as_u64().is_some_and(|u| u <= u32::MAX as u64)) {
        let nums = xs.into_iter()
            .map(|v| v.as_u64().expect("checked") as u32)
            .collect();
        return Ok(Value::ListU32(nums));
    }
    Err("array elements must all be strings or all be u32-fitting non-negative integers".into())
}

fn value_to_json_value(v: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    match v {
        Value::Unit => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::U8(v) => (*v).into(),
        Value::U16(v) => (*v).into(),
        Value::U32(v) => (*v).into(),
        Value::U64(v) => (*v).into(),
        Value::I32(v) => (*v).into(),
        Value::I64(v) => (*v).into(),
        Value::Str(s) => J::String(s.clone()),
        Value::Bytes(b) => J::String(hex_encode(b)),
        Value::ListU32(xs) => J::Array(xs.iter().map(|x| (*x).into()).collect()),
        Value::ListStr(xs) => J::Array(xs.iter().map(|s| J::String(s.clone())).collect()),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
