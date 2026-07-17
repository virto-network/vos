//! Bridge between vos's flat dynamic [`Value`](vos::value::Value) and
//! nushell's rich [`Value`](nu_protocol::Value).
//!
//! * **vos → nu** is *total*: every vos reply renders as a nu value.
//! * **nu → vos** is *checked*: arguments are coerced against the actor's
//!   declared field type. Records, floats, and nested lists are rejected —
//!   vos's `Value` has no variant for them. That rejection is the flatness
//!   guarantee, structurally tied to the absence of those vos variants.

use nu_protocol::{Span, Value as NuValue};
use vos::value::Value as VosValue;

// ── vos → nu (reply rendering) ───────────────────────────────────────────

/// Render a vos reply value as a nushell value. Total — never fails.
pub fn vos_to_nu(v: VosValue, span: Span) -> NuValue {
    match v {
        VosValue::Unit => NuValue::nothing(span),
        VosValue::Bool(b) => NuValue::bool(b, span),
        VosValue::U8(n) => NuValue::int(i64::from(n), span),
        VosValue::U16(n) => NuValue::int(i64::from(n), span),
        VosValue::U32(n) => NuValue::int(i64::from(n), span),
        // nu ints are i64; a u64 that overflows degrades to a string so the
        // value is never silently truncated.
        VosValue::U64(n) => match i64::try_from(n) {
            Ok(i) => NuValue::int(i, span),
            Err(_) => NuValue::string(n.to_string(), span),
        },
        VosValue::I32(n) => NuValue::int(i64::from(n), span),
        VosValue::I64(n) => NuValue::int(n, span),
        VosValue::Str(s) => NuValue::string(s, span),
        VosValue::Bytes(b) => NuValue::binary(b, span),
        VosValue::ListU32(xs) => NuValue::list(
            xs.into_iter()
                .map(|n| NuValue::int(i64::from(n), span))
                .collect(),
            span,
        ),
        VosValue::ListStr(xs) => NuValue::list(
            xs.into_iter().map(|s| NuValue::string(s, span)).collect(),
            span,
        ),
    }
}

/// Render a nushell value as plain text for the output pane / exec stdout.
/// Deliberately avoids nu-command's table viewer (not a dependency): scalars
/// stringify, lists join one-per-line, binary renders as hex.
pub fn render_value(v: &NuValue) -> String {
    use nu_protocol::Type;
    if matches!(v.get_type(), Type::Nothing) {
        return String::new();
    }
    if let Ok(list) = v.as_list() {
        return list.iter().map(render_value).collect::<Vec<_>>().join("\n");
    }
    if let Ok(bin) = v.as_binary() {
        return bin.iter().map(|b| format!("{b:02x}")).collect::<String>();
    }
    v.coerce_str()
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| format!("<{}>", v.get_type()))
}

// ── nu → vos (argument coercion) ─────────────────────────────────────────

/// Coerce a nushell argument value into a typed vos value, guided by the
/// actor's declared field type string (`ParsedField.ty`, e.g. `"u64"`,
/// `"String"`, `"Vec<u8>"`). Unknown/empty types fall back to a best-effort
/// heuristic. Returns a human-readable error on mismatch.
pub fn nu_to_vos_typed(v: &NuValue, ty: &str) -> Result<VosValue, String> {
    match ty {
        "u8" => {
            let i = req_int(v)?;
            u8::try_from(i)
                .map(VosValue::U8)
                .map_err(|_| out_of_range(i, ty))
        }
        "u16" => {
            let i = req_int(v)?;
            u16::try_from(i)
                .map(VosValue::U16)
                .map_err(|_| out_of_range(i, ty))
        }
        "u32" => {
            let i = req_int(v)?;
            u32::try_from(i)
                .map(VosValue::U32)
                .map_err(|_| out_of_range(i, ty))
        }
        "u64" => {
            let i = req_int(v)?;
            u64::try_from(i)
                .map(VosValue::U64)
                .map_err(|_| out_of_range(i, ty))
        }
        "i32" => {
            let i = req_int(v)?;
            i32::try_from(i)
                .map(VosValue::I32)
                .map_err(|_| out_of_range(i, ty))
        }
        "i64" => Ok(VosValue::I64(req_int(v)?)),
        "bool" => Ok(VosValue::Bool(req_bool(v)?)),
        "String" | "str" | "&str" | "&'static str" => Ok(VosValue::Str(req_str(v)?)),
        "Vec<u8>" => bytes_from(v),
        "Vec<u32>" => list_u32_from(v),
        "Vec<String>" | "Vec<&str>" => list_str_from(v),
        _ => nu_to_vos_heuristic(v),
    }
}

/// Best-effort coercion when no schema type is known. Mirrors `vosx`'s
/// no-schema fallback: int → U64 (or I64 if negative), bool → Bool, string →
/// Str, with list and binary support. Records/floats/nested lists error.
pub fn nu_to_vos_heuristic(v: &NuValue) -> Result<VosValue, String> {
    if let Ok(b) = v.as_bool() {
        return Ok(VosValue::Bool(b));
    }
    if let Ok(i) = v.as_int() {
        return Ok(if i < 0 {
            VosValue::I64(i)
        } else {
            VosValue::U64(i as u64)
        });
    }
    if let Ok(s) = v.as_str() {
        return Ok(VosValue::Str(s.to_string()));
    }
    if let Ok(b) = v.as_binary() {
        return Ok(VosValue::Bytes(b.to_vec()));
    }
    if v.as_list().is_ok() {
        // Prefer a u32 list; fall back to a string list.
        return list_u32_from(v).or_else(|_| list_str_from(v));
    }
    Err(unsupported(v))
}

// ── helpers ──────────────────────────────────────────────────────────────

fn req_int(v: &NuValue) -> Result<i64, String> {
    v.as_int()
        .map_err(|_| format!("expected an integer, got {}", v.get_type()))
}

fn req_bool(v: &NuValue) -> Result<bool, String> {
    v.as_bool()
        .map_err(|_| format!("expected a boolean, got {}", v.get_type()))
}

fn req_str(v: &NuValue) -> Result<String, String> {
    v.as_str()
        .map(str::to_string)
        .map_err(|_| format!("expected a string, got {}", v.get_type()))
}

fn bytes_from(v: &NuValue) -> Result<VosValue, String> {
    if let Ok(b) = v.as_binary() {
        return Ok(VosValue::Bytes(b.to_vec()));
    }
    let list = v
        .as_list()
        .map_err(|_| format!("expected binary or a list of bytes, got {}", v.get_type()))?;
    let mut out = Vec::with_capacity(list.len());
    for el in list {
        let i = req_int(el)?;
        out.push(u8::try_from(i).map_err(|_| out_of_range(i, "u8"))?);
    }
    Ok(VosValue::Bytes(out))
}

fn list_u32_from(v: &NuValue) -> Result<VosValue, String> {
    let list = v
        .as_list()
        .map_err(|_| format!("expected a list, got {}", v.get_type()))?;
    let mut out = Vec::with_capacity(list.len());
    for el in list {
        let i = req_int(el)?;
        out.push(u32::try_from(i).map_err(|_| out_of_range(i, "u32"))?);
    }
    Ok(VosValue::ListU32(out))
}

fn list_str_from(v: &NuValue) -> Result<VosValue, String> {
    let list = v
        .as_list()
        .map_err(|_| format!("expected a list, got {}", v.get_type()))?;
    let mut out = Vec::with_capacity(list.len());
    for el in list {
        out.push(req_str(el)?);
    }
    Ok(VosValue::ListStr(out))
}

fn out_of_range(i: i64, ty: &str) -> String {
    format!("{i} is out of range for `{ty}`")
}

fn unsupported(v: &NuValue) -> String {
    format!(
        "unsupported argument type `{}` — actor arguments are flat scalars or lists of int/string",
        v.get_type()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nu_protocol::Record;

    fn span() -> Span {
        Span::test_data()
    }

    // ── vos → nu ──────────────────────────────────────────────
    #[test]
    fn vos_to_nu_scalars() {
        assert!(matches!(
            vos_to_nu(VosValue::Unit, span()),
            NuValue::Nothing { .. }
        ));
        assert_eq!(
            vos_to_nu(VosValue::Bool(true), span()).as_bool().unwrap(),
            true
        );
        assert_eq!(vos_to_nu(VosValue::U32(42), span()).as_int().unwrap(), 42);
        assert_eq!(vos_to_nu(VosValue::I64(-7), span()).as_int().unwrap(), -7);
        assert_eq!(
            vos_to_nu(VosValue::Str("hi".into()), span())
                .as_str()
                .unwrap(),
            "hi"
        );
        assert_eq!(
            vos_to_nu(VosValue::Bytes(vec![1, 2, 3]), span())
                .as_binary()
                .unwrap(),
            &[1, 2, 3]
        );
    }

    #[test]
    fn u64_overflow_degrades_to_string() {
        let big = u64::MAX;
        let nu = vos_to_nu(VosValue::U64(big), span());
        assert_eq!(nu.as_str().unwrap(), big.to_string());
        // A u64 within i64 range stays an int.
        assert_eq!(vos_to_nu(VosValue::U64(5), span()).as_int().unwrap(), 5);
    }

    #[test]
    fn vos_to_nu_lists() {
        let l = vos_to_nu(VosValue::ListU32(vec![1, 2]), span());
        let items = l.as_list().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].as_int().unwrap(), 1);

        let s = vos_to_nu(VosValue::ListStr(vec!["a".into(), "b".into()]), span());
        assert_eq!(s.as_list().unwrap()[1].as_str().unwrap(), "b");
    }

    // ── nu → vos (typed) ──────────────────────────────────────
    #[test]
    fn typed_unsigned_ok_and_rejects_negative_and_overflow() {
        assert_eq!(
            nu_to_vos_typed(&NuValue::int(5, span()), "u64").unwrap(),
            VosValue::U64(5)
        );
        assert!(nu_to_vos_typed(&NuValue::int(-1, span()), "u64").is_err());
        assert!(nu_to_vos_typed(&NuValue::int(300, span()), "u8").is_err());
        assert_eq!(
            nu_to_vos_typed(&NuValue::int(255, span()), "u8").unwrap(),
            VosValue::U8(255)
        );
    }

    #[test]
    fn typed_signed_and_bool_and_string() {
        assert_eq!(
            nu_to_vos_typed(&NuValue::int(-5, span()), "i32").unwrap(),
            VosValue::I32(-5)
        );
        assert_eq!(
            nu_to_vos_typed(&NuValue::bool(true, span()), "bool").unwrap(),
            VosValue::Bool(true)
        );
        assert_eq!(
            nu_to_vos_typed(&NuValue::string("x", span()), "String").unwrap(),
            VosValue::Str("x".into())
        );
    }

    #[test]
    fn typed_rejects_wrong_scalar_kind() {
        // string where an int is wanted
        assert!(nu_to_vos_typed(&NuValue::string("5", span()), "u64").is_err());
        // int where a bool is wanted
        assert!(nu_to_vos_typed(&NuValue::int(1, span()), "bool").is_err());
        // int where a string is wanted
        assert!(nu_to_vos_typed(&NuValue::int(1, span()), "String").is_err());
    }

    #[test]
    fn typed_lists() {
        let list = NuValue::list(
            vec![NuValue::int(1, span()), NuValue::int(2, span())],
            span(),
        );
        assert_eq!(
            nu_to_vos_typed(&list, "Vec<u32>").unwrap(),
            VosValue::ListU32(vec![1, 2])
        );

        let strs = NuValue::list(vec![NuValue::string("a", span())], span());
        assert_eq!(
            nu_to_vos_typed(&strs, "Vec<String>").unwrap(),
            VosValue::ListStr(vec!["a".into()])
        );

        let bytes = NuValue::binary(vec![9u8, 8], span());
        assert_eq!(
            nu_to_vos_typed(&bytes, "Vec<u8>").unwrap(),
            VosValue::Bytes(vec![9, 8])
        );
    }

    // ── flatness guarantee ────────────────────────────────────
    #[test]
    fn flatness_rejects_record_float_nested() {
        let record = NuValue::record(Record::new(), span());
        assert!(nu_to_vos_heuristic(&record).is_err());
        assert!(nu_to_vos_typed(&record, "u64").is_err());

        let float = NuValue::float(1.5, span());
        assert!(nu_to_vos_heuristic(&float).is_err());
        assert!(nu_to_vos_typed(&float, "i64").is_err());

        let nested = NuValue::list(
            vec![NuValue::list(vec![NuValue::int(1, span())], span())],
            span(),
        );
        assert!(nu_to_vos_typed(&nested, "Vec<u32>").is_err());
    }

    // ── heuristic (no schema) ─────────────────────────────────
    #[test]
    fn heuristic_picks_sensible_variants() {
        assert_eq!(
            nu_to_vos_heuristic(&NuValue::int(7, span())).unwrap(),
            VosValue::U64(7)
        );
        assert_eq!(
            nu_to_vos_heuristic(&NuValue::int(-7, span())).unwrap(),
            VosValue::I64(-7)
        );
        assert_eq!(
            nu_to_vos_heuristic(&NuValue::bool(false, span())).unwrap(),
            VosValue::Bool(false)
        );
        assert_eq!(
            nu_to_vos_heuristic(&NuValue::string("hey", span())).unwrap(),
            VosValue::Str("hey".into())
        );
    }
}
