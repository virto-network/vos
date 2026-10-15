//! Names: ids derived from them, and the cases generated items take.

use std::collections::BTreeMap;

use proc_macro2::Span;
use syn::Error;
use vos_wire::ids::derive_id;

/// Track derived ids: 0 is reserved and two names must not share one.
pub(crate) struct Ids {
    what: &'static str,
    seen: BTreeMap<u32, String>,
}

impl Ids {
    pub(crate) fn new(what: &'static str) -> Self {
        Self {
            what,
            seen: BTreeMap::new(),
        }
    }

    pub(crate) fn take(&mut self, domain: &str, name: &str, span: Span) -> syn::Result<u32> {
        let id = derive_id(domain, name);
        if id == 0 {
            return Err(Error::new(
                span,
                format!(
                    "{} `{name}` derives the reserved id 0; name it explicitly",
                    self.what
                ),
            ));
        }
        if let Some(other) = self.seen.insert(id, name.to_owned()) {
            return Err(Error::new(
                span,
                format!(
                    "{} `{name}` derives the same id as `{other}`; name one explicitly",
                    self.what
                ),
            ));
        }
        Ok(id)
    }
}

pub(crate) fn upper_camel(name: &str) -> String {
    name.split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            let first = chars.next().expect("non-empty").to_ascii_uppercase();
            core::iter::once(first).chain(chars).collect::<String>()
        })
        .collect()
}

/// `Ledger` → `ledger`, `HttpServer` and `HTTPServer` → `http_server`.
pub(crate) fn snake(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let mut out = String::new();
    for (index, &c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase() && index > 0 {
            let previous = chars[index - 1];
            let next_lower = chars.get(index + 1).is_some_and(char::is_ascii_lowercase);
            if previous.is_ascii_lowercase()
                || previous.is_ascii_digit()
                || (previous.is_ascii_uppercase() && next_lower)
            {
                out.push('_');
            }
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::snake;

    #[test]
    fn snake_case_keeps_acronyms_together() {
        assert_eq!(snake("Ledger"), "ledger");
        assert_eq!(snake("HttpServer"), "http_server");
        assert_eq!(snake("HTTPServer"), "http_server");
        assert_eq!(snake("Erc20Token"), "erc20_token");
    }
}
