//! Host helper for the dev-project actor's `BlobKind::RustAst`
//! payloads.
//!
//! The dev extension wraps a `syn::File` round-trip
//! (`syn::parse_file` → `prettyplease::unparse`) and stores the
//! canonical UTF-8 text as the AST blob bytes. Two semantically-
//! equivalent sources that differ only in whitespace or comments
//! end up byte-identical, so the AST blob's hash dedupes across
//! those cosmetic changes — which is what the structural-edit
//! workflow needs.
//!
//! v2 considered storing an rkyv-archived mirror of `syn::File`
//! instead, but `syn` doesn't expose its tree types as rkyv-able
//! and mirroring the surface (every expression, every pattern…)
//! is a much bigger project than the dedup feature warrants. The
//! canonical text gives us 90% of the value: structural-equality
//! by hash, lossless round-trip through `prettyplease`. A future
//! commit can introduce a real archive if/when AST-aware tooling
//! lands.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// `syn::parse_file` rejected the source.
    #[error("rust syntax error: {0}")]
    Parse(#[from] syn::Error),
    /// The stored AST blob isn't valid UTF-8 — shouldn't happen
    /// for blobs produced by `text_to_ast` but a corrupted store
    /// or hand-built blob could trigger it.
    #[error("ast blob is not valid utf-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

/// Parse Rust source into a canonical `syn::File` and render it
/// back to text. The returned bytes are what the dev-project
/// actor stores as a `BlobKind::RustAst` blob.
///
/// Canonicalisation throws away comments and exact whitespace —
/// two sources that differ only in those produce identical
/// bytes here.
pub fn text_to_ast(src: &str) -> Result<Vec<u8>, Error> {
    let file: syn::File = syn::parse_file(src)?;
    let canonical = prettyplease::unparse(&file);
    Ok(canonical.into_bytes())
}

/// Render an AST blob back to text. v1 of the blob format is
/// canonical UTF-8 source, so this just validates UTF-8 and
/// hands it back.
pub fn ast_to_text(bytes: &[u8]) -> Result<String, Error> {
    let s = std::str::from_utf8(bytes)?;
    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COUNTER: &str = r#"
use vos::prelude::*;

#[actor]
pub struct Counter {
    count: u32,
}

#[messages]
impl Counter {
    fn new() -> Self {
        Self { count: 0 }
    }

    #[msg]
    async fn inc(&mut self) -> u32 {
        self.count += 1;
        self.count
    }
}
"#;

    #[test]
    fn roundtrip_is_idempotent() {
        let ast = text_to_ast(COUNTER).expect("parse counter");
        let text = ast_to_text(&ast).expect("ast back to text");
        let ast2 = text_to_ast(&text).expect("reparse canonical text");
        assert_eq!(
            ast, ast2,
            "second round-trip should produce identical AST bytes"
        );
    }

    #[test]
    fn whitespace_differences_normalise() {
        let crowded = "fn f ( ) { 1 + 2 ; }";
        let spacey = "fn f() {\n    1 + 2;\n}\n";
        let a = text_to_ast(crowded).expect("parse crowded");
        let b = text_to_ast(spacey).expect("parse spacey");
        assert_eq!(a, b, "spacing differences should canonicalise away");
    }

    #[test]
    fn comments_get_stripped() {
        let with_comment = "// the counter\nfn f() {}\n";
        let without = "fn f() {}\n";
        let a = text_to_ast(with_comment).expect("parse with comment");
        let b = text_to_ast(without).expect("parse without");
        // prettyplease drops `//` line comments outside doc-comment
        // attributes; the resulting AST blobs are identical.
        assert_eq!(a, b, "line comments should canonicalise away");
    }

    #[test]
    fn invalid_source_errors_loudly() {
        let bad = "fn f( {";
        let r = text_to_ast(bad);
        assert!(matches!(r, Err(Error::Parse(_))));
    }
}
