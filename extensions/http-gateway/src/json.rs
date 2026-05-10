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
    let json: serde_json::Value = serde_json::from_slice(body).map_err(|e| format!("{e}"))?;
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
        return Ok(if u <= u32::MAX as u64 {
            Value::U32(u as u32)
        } else {
            Value::U64(u)
        });
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
        let strings = xs
            .into_iter()
            .map(|v| match v {
                serde_json::Value::String(s) => s,
                _ => unreachable!(),
            })
            .collect();
        return Ok(Value::ListStr(strings));
    }
    if xs
        .iter()
        .all(|v| v.as_u64().is_some_and(|u| u <= u32::MAX as u64))
    {
        let nums = xs
            .into_iter()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v(b: &[u8]) -> Vec<(String, Value)> {
        parse_flat_json(b).expect("parse")
    }

    #[test]
    fn parse_empty_object() {
        assert!(v(b"{}").is_empty());
    }

    #[test]
    fn parse_string() {
        assert_eq!(
            v(br#"{"k":"hello"}"#),
            vec![("k".into(), Value::Str("hello".into()))]
        );
    }

    #[test]
    fn parse_bool_null() {
        let pairs = v(br#"{"a":true,"b":false,"c":null}"#);
        assert_eq!(pairs.len(), 3);
        assert!(matches!(pairs[0].1, Value::Bool(true)));
        assert!(matches!(pairs[1].1, Value::Bool(false)));
        assert!(matches!(pairs[2].1, Value::Unit));
    }

    #[test]
    fn parse_numbers_narrow_to_smallest_fitting() {
        // serde_json's `Map` is BTreeMap-backed by default, so input
        // order isn't preserved; look up by key.
        let pairs = v(br#"{"u32":42,"u64":5000000000,"neg":-7}"#);
        let by_key = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        assert!(matches!(by_key("u32"), Some(Value::U32(42))));
        assert!(matches!(by_key("u64"), Some(Value::U64(5_000_000_000))));
        assert!(matches!(by_key("neg"), Some(Value::I64(-7))));
    }

    #[test]
    fn parse_string_array() {
        let pairs = v(br#"{"xs":["a","b"]}"#);
        match &pairs[0].1 {
            Value::ListStr(xs) => assert_eq!(xs, &vec!["a".to_string(), "b".to_string()]),
            other => panic!("expected ListStr, got {other:?}"),
        }
    }

    #[test]
    fn parse_u32_array() {
        let pairs = v(br#"{"xs":[1,2,3]}"#);
        match &pairs[0].1 {
            Value::ListU32(xs) => assert_eq!(xs, &vec![1u32, 2, 3]),
            other => panic!("expected ListU32, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_non_object_root() {
        assert!(parse_flat_json(b"[1,2]").is_err());
        assert!(parse_flat_json(br#""hi""#).is_err());
    }

    #[test]
    fn parse_rejects_nested_object() {
        assert!(parse_flat_json(br#"{"k":{"x":1}}"#).is_err());
    }

    #[test]
    fn parse_rejects_floats() {
        assert!(parse_flat_json(br#"{"k":1.5}"#).is_err());
    }

    #[test]
    fn parse_rejects_mixed_array() {
        assert!(parse_flat_json(br#"{"xs":[1,"a"]}"#).is_err());
    }

    #[test]
    fn render_primitives() {
        assert_eq!(value_to_json(&Value::Unit), b"null");
        assert_eq!(value_to_json(&Value::Bool(true)), b"true");
        assert_eq!(value_to_json(&Value::U32(42)), b"42");
        assert_eq!(value_to_json(&Value::I64(-1)), b"-1");
        assert_eq!(value_to_json(&Value::Str("hi".into())), br#""hi""#);
    }

    #[test]
    fn render_bytes_as_hex_string() {
        assert_eq!(value_to_json(&Value::Bytes(vec![0xde, 0xad])), br#""dead""#);
    }

    #[test]
    fn render_lists() {
        assert_eq!(value_to_json(&Value::ListU32(vec![1, 2, 3])), b"[1,2,3]");
        assert_eq!(
            value_to_json(&Value::ListStr(vec!["a".into(), "b".into()])),
            br#"["a","b"]"#
        );
    }

    #[test]
    fn parse_keeps_all_keys() {
        // Order isn't part of the contract (serde_json::Map is
        // BTreeMap-backed by default), so just check the set.
        let pairs = v(br#"{"alpha":"a","beta":42}"#);
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(pairs.len(), 2);
        assert!(keys.contains(&"alpha"));
        assert!(keys.contains(&"beta"));
    }
}
