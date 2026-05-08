//! CLI output mode — text (default, human-readable) or JSON
//! (for scripting / LLM consumption).
//!
//! The choice is set once in `main` from `--format` and read
//! by individual commands. A static `OnceLock` is the simplest
//! way to thread the flag through every `run()` without
//! plumbing it into 20-odd signatures.

use std::sync::OnceLock;

use clap::ValueEnum;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable tabular output (default).
    #[default]
    Text,
    /// Machine-readable JSON. Designed for LLMs and shell
    /// pipelines — every command that opts in emits a single
    /// well-formed JSON value to stdout.
    Json,
}

static FORMAT: OnceLock<Format> = OnceLock::new();

pub fn set(format: Format) {
    let _ = FORMAT.set(format);
}

pub fn current() -> Format {
    FORMAT.get().copied().unwrap_or_default()
}

pub fn is_json() -> bool {
    matches!(current(), Format::Json)
}

/// Serialize `value` to a single-line JSON string and print it
/// to stdout. Use from commands that have already decided JSON
/// is the active mode.
pub fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("vosx: failed to serialize JSON: {e}"),
    }
}

/// Convert a `vos::value::Value` (the dynamic reply type from
/// `space call`) into a `serde_json::Value`. Bytes become
/// hex-encoded strings for symmetry with the rest of the CLI;
/// `Unit` collapses to `null`.
pub fn value_to_json(v: &vos::value::Value) -> serde_json::Value {
    use serde_json::{Number, Value as J};
    use vos::value::Value as V;
    match v {
        V::Unit => J::Null,
        V::Bool(b) => J::Bool(*b),
        V::U8(n) => J::Number((*n as u64).into()),
        V::U16(n) => J::Number((*n as u64).into()),
        V::U32(n) => J::Number((*n as u64).into()),
        V::U64(n) => J::Number((*n).into()),
        V::I32(n) => J::Number((*n as i64).into()),
        V::I64(n) => Number::from_f64(*n as f64)
            .map(J::Number)
            .unwrap_or_else(|| J::String(n.to_string())),
        V::Str(s) => J::String(s.clone()),
        V::Bytes(b) => J::String(format!("0x{}", hex::encode(b))),
        V::ListU32(xs) => J::Array(xs.iter().map(|x| J::Number((*x as u64).into())).collect()),
        V::ListStr(xs) => J::Array(xs.iter().map(|s| J::String(s.clone())).collect()),
    }
}
