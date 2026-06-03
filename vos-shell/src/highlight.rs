//! Nu-syntax highlighting for the console prompt.
//!
//! Reuses `nu_parser::flatten_block` — the same tokens-to-shapes pass nushell's
//! own highlighter uses — and maps each shape to a coarse colour category. The
//! TUI maps [`HlKind`] to actual colours; nothing here depends on ratatui, so
//! the engine layer stays UI-agnostic.

use nu_parser::FlatShape;
use nu_protocol::engine::{EngineState, StateWorkingSet};

/// Coarse syntax category for one run of input text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HlKind {
    Command,
    External,
    Flag,
    String,
    Number,
    Variable,
    Keyword,
    Operator,
    Garbage,
    Plain,
}

/// A run of input text plus its syntax category. Concatenating every `text`
/// reproduces the original input exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HlSpan {
    pub text: String,
    pub kind: HlKind,
}

fn map_shape(shape: &FlatShape) -> HlKind {
    match shape {
        FlatShape::InternalCall(_) | FlatShape::Custom(_) => HlKind::Command,
        FlatShape::External(_) | FlatShape::ExternalArg | FlatShape::ExternalResolved => {
            HlKind::External
        }
        FlatShape::Flag => HlKind::Flag,
        FlatShape::String
        | FlatShape::RawString
        | FlatShape::StringInterpolation
        | FlatShape::GlobPattern
        | FlatShape::GlobInterpolation
        | FlatShape::Filepath
        | FlatShape::Directory => HlKind::String,
        FlatShape::Int
        | FlatShape::Float
        | FlatShape::Range
        | FlatShape::Bool
        | FlatShape::Binary
        | FlatShape::DateTime
        | FlatShape::Nothing => HlKind::Number,
        FlatShape::Variable(_) | FlatShape::VarDecl(_) => HlKind::Variable,
        FlatShape::Keyword => HlKind::Keyword,
        FlatShape::Operator | FlatShape::Pipe | FlatShape::Redirection => HlKind::Operator,
        FlatShape::Garbage => HlKind::Garbage,
        _ => HlKind::Plain,
    }
}

fn push_run(out: &mut Vec<HlSpan>, text: &str, kind: HlKind) {
    if text.is_empty() {
        return;
    }
    // Coalesce adjacent runs of the same kind.
    if let Some(last) = out.last_mut() {
        if last.kind == kind {
            last.text.push_str(text);
            return;
        }
    }
    out.push(HlSpan {
        text: text.to_string(),
        kind,
    });
}

/// Tokenize `line` and return contiguous coloured runs covering the whole
/// string (gaps between tokens are `Plain`). Parses against a throwaway working
/// set derived from `engine_state`; no state is mutated.
pub fn highlight(engine_state: &EngineState, line: &str) -> Vec<HlSpan> {
    let mut ws = StateWorkingSet::new(engine_state);
    // Spans are absolute offsets into the working set's accumulated buffer;
    // subtract where our input begins to get offsets into `line`.
    let offset = ws.next_span_start();
    let block = nu_parser::parse(&mut ws, None, line.as_bytes(), false);
    let shapes = nu_parser::flatten_block(&ws, &block);

    let len = line.len();
    let mut out: Vec<HlSpan> = Vec::new();
    let mut cursor = 0usize;
    for (span, shape) in shapes {
        let start = span.start.saturating_sub(offset);
        let end = span.end.saturating_sub(offset);
        // Skip out-of-range, zero-width, overlapping, or non-boundary spans.
        if start >= end || end > len || start < cursor {
            continue;
        }
        if !line.is_char_boundary(start) || !line.is_char_boundary(end) {
            continue;
        }
        if start > cursor {
            push_run(&mut out, &line[cursor..start], HlKind::Plain);
        }
        push_run(&mut out, &line[start..end], map_shape(&shape));
        cursor = end;
    }
    if cursor < len {
        push_run(&mut out, &line[cursor..], HlKind::Plain);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox;

    fn joined(spans: &[HlSpan]) -> String {
        spans.iter().map(|s| s.text.as_str()).collect()
    }

    #[test]
    fn covers_whole_input() {
        let es = sandbox::base_engine_state();
        for line in [
            "",
            "   ",
            "length",
            "[1 2 3] | length",
            "if true { 1 } else { 2 }",
        ] {
            assert_eq!(
                joined(&highlight(&es, line)),
                line,
                "round-trip for {line:?}"
            );
        }
    }

    #[test]
    fn classifies_common_shapes() {
        let es = sandbox::base_engine_state();

        let spans = highlight(&es, "\"hi\" | length");
        assert!(
            spans.iter().any(|s| s.kind == HlKind::String),
            "string: {spans:?}"
        );
        assert!(
            spans.iter().any(|s| s.kind == HlKind::Operator),
            "pipe: {spans:?}"
        );

        let spans = highlight(&es, "123");
        assert!(
            spans.iter().any(|s| s.kind == HlKind::Number),
            "int: {spans:?}"
        );

        // `if` is implemented as a command in nushell → classified Command
        // (and coloured like one), matching nushell's own highlighter.
        let spans = highlight(&es, "if true { 1 }");
        assert!(
            spans.iter().any(|s| s.kind == HlKind::Command),
            "command: {spans:?}"
        );
        assert!(
            spans.iter().any(|s| s.kind == HlKind::Number),
            "bool/int: {spans:?}"
        );
    }
}
