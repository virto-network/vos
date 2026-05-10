//! Operator-controlled config carried as actor init args.
//!
//! `GatewayConfig` is a field on the [`HttpGateway`](crate::HttpGateway)
//! actor. The values come from the worker manifest's `init = { … }`
//! table and survive across warm restarts via rkyv. The actor's
//! `start` handler installs the live config into a process-global
//! [`OnceLock`] so the connection tasks (which don't have access to
//! the actor's `&self`) can read it.
//!
//! All five fields are typed as `String` because the macro-driven
//! init-args extraction supports primitives + `String`. **Empty
//! string means "use the default"**, which keeps the manifest concise
//! for dev deployments — only override what you care about.
//!
//! ## Manifest example
//!
//! ```toml
//! [[worker]]
//! name = "gateway"
//! path = "target/release/libhttp_gateway.so"
//! init = {
//!     bind_addr   = "0.0.0.0",
//!     auth_token  = "abc123…",     # production: required for non-loopback
//!     admin_token = "different…",  # production: required to expose /__admin
//!     tls_cert    = "/etc/tls/cert.pem",
//!     tls_key     = "/etc/tls/key.pem",
//! }
//! ```
//!
//! ## Defaults (when the field is empty)
//!
//! | Field         | Default                                   |
//! |---------------|-------------------------------------------|
//! | `bind_addr`   | `127.0.0.1`                                |
//! | `auth_token`  | none (open dispatch + WARN at startup)    |
//! | `admin_token` | none (`/__admin/*` returns 404)           |
//! | `tls_cert`    | none (h3 self-signs `localhost`, dev only)|
//! | `tls_key`    | none (paired with `tls_cert`)             |

use std::net::{IpAddr, Ipv4Addr};

use vos::log;

/// Init-args carried into [`HttpGateway`](crate::HttpGateway). Auto-
/// derives rkyv via the actor macro, so a warm restart restores the
/// same config without re-reading the manifest. Stored on
/// [`crate::state::Inner`] so each gateway instance gets its own
/// config — process-globals were a footgun for tests.
#[derive(vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Default)]
#[rkyv(crate = vos::rkyv)]
pub(crate) struct GatewayConfig {
    pub(crate) bind_addr: String,
    pub(crate) auth_token: String,
    pub(crate) admin_token: String,
    pub(crate) tls_cert: String,
    pub(crate) tls_key: String,
}

impl GatewayConfig {
    /// Bind IP. `127.0.0.1` when `bind_addr` is empty / unparseable.
    pub(crate) fn bind_ip(&self) -> IpAddr {
        let raw = self.bind_addr.as_str();
        if raw.is_empty() {
            return IpAddr::V4(Ipv4Addr::LOCALHOST);
        }
        raw.parse().unwrap_or_else(|_| {
            log::warn!("http-gateway: bind_addr {raw:?} unparseable; falling back to 127.0.0.1");
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        })
    }

    pub(crate) fn auth_token(&self) -> Option<&str> {
        let t = self.auth_token.as_str();
        (!t.is_empty()).then_some(t)
    }

    pub(crate) fn admin_token(&self) -> Option<&str> {
        let t = self.admin_token.as_str();
        (!t.is_empty()).then_some(t)
    }

    /// Both PEM paths or `None`. Returns `None` if either is empty so
    /// callers fall back to a self-signed cert.
    #[cfg(feature = "http3")]
    pub(crate) fn tls_paths(&self) -> Option<(&str, &str)> {
        let cert = self.tls_cert.as_str();
        let key = self.tls_key.as_str();
        (!cert.is_empty() && !key.is_empty()).then_some((cert, key))
    }
}

/// Constant-time equality check. Length differences leak (early
/// return), which is acceptable for high-entropy tokens — the
/// expectation is operator-generated random secrets, not user
/// passwords.
pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Find a header value (case-insensitive on name).
pub(crate) fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_matches() {
        assert!(ct_eq("abc", "abc"));
    }

    #[test]
    fn ct_eq_differs_same_length() {
        assert!(!ct_eq("abc", "abd"));
    }

    #[test]
    fn ct_eq_differs_length() {
        assert!(!ct_eq("abc", "abcd"));
        assert!(!ct_eq("", "x"));
        assert!(ct_eq("", ""));
    }

    #[test]
    fn header_value_case_insensitive_name() {
        let headers = vec![
            ("authorization".into(), "Bearer abc".into()),
            ("x-foo".into(), "bar".into()),
        ];
        assert_eq!(header_value(&headers, "Authorization"), Some("Bearer abc"));
        assert_eq!(header_value(&headers, "AUTHORIZATION"), Some("Bearer abc"));
        assert_eq!(header_value(&headers, "x-FOO"), Some("bar"));
    }

    #[test]
    fn header_value_missing_returns_none() {
        let headers: Vec<(String, String)> = vec![];
        assert_eq!(header_value(&headers, "x"), None);
    }

    #[test]
    fn header_value_returns_first_match() {
        let headers = vec![("x".into(), "first".into()), ("x".into(), "second".into())];
        assert_eq!(header_value(&headers, "x"), Some("first"));
    }
}
