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
//!     bind_addr     = "0.0.0.0",
//!     auth_token    = "abc123…",     # production: required for non-loopback
//!     admin_token   = "different…",  # production: required to expose /__admin
//!     tls_cert      = "/etc/tls/cert.pem",
//!     tls_key       = "/etc/tls/key.pem",
//!     agent_tokens  = "math:tok1,greeter:tok2",  # per-agent override (optional)
//! }
//! ```
//!
//! ## Defaults (when the field is empty)
//!
//! | Field          | Default                                   |
//! |----------------|-------------------------------------------|
//! | `bind_addr`    | `127.0.0.1`                                |
//! | `auth_token`   | none (open dispatch + WARN at startup)    |
//! | `admin_token`  | none (`/__admin/*` returns 404)           |
//! | `tls_cert`     | none (h3 self-signs `localhost`, dev only)|
//! | `tls_key`      | none (paired with `tls_cert`)             |
//! | `agent_tokens` | empty (no per-agent override)             |

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
    /// Per-agent Bearer tokens. Encoded as
    /// `agent:token,agent:token` because manifest init args are
    /// flat (no nested maps). Whitespace around `,` and `:` is
    /// stripped. Empty entries skipped. When set for an agent,
    /// requests to `/<agent>/*` require that token instead of
    /// the global one — pre-`/<agent>/*` URLs (admin, schema,
    /// metrics) ignore this entirely.
    pub(crate) agent_tokens: String,
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

    /// Parse `agent_tokens` into a (agent_name → bearer_token) map.
    /// Fails loudly on any malformed entry — a typo'd manifest
    /// previously yielded a silently-unprotected agent, which is
    /// the kind of regression a Bearer-auth config absolutely
    /// shouldn't produce. Entry rules:
    ///
    ///   * Must contain exactly one `:` separating the agent name
    ///     from the token.
    ///   * Neither side may be empty after trim.
    ///
    /// Returns a human-readable error listing every malformed
    /// position; gateway `run()` logs it and exits non-zero so the
    /// host treats it as a hard config failure.
    pub(crate) fn parse_agent_tokens(
        &self,
    ) -> Result<std::collections::HashMap<String, String>, String> {
        let raw = self.agent_tokens.trim();
        if raw.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let mut map = std::collections::HashMap::new();
        let mut errors: Vec<String> = Vec::new();
        for (idx, entry) in raw.split(',').enumerate() {
            let entry = entry.trim();
            if entry.is_empty() {
                errors.push(format!("entry #{}: empty (stray comma?)", idx + 1));
                continue;
            }
            let Some((agent, token)) = entry.split_once(':') else {
                errors.push(format!(
                    "entry #{}: missing `:` separator in {entry:?}",
                    idx + 1,
                ));
                continue;
            };
            let agent = agent.trim();
            let token = token.trim();
            if agent.is_empty() {
                errors.push(format!("entry #{}: empty agent name", idx + 1));
                continue;
            }
            if token.is_empty() {
                errors.push(format!(
                    "entry #{}: empty token for agent {agent:?}",
                    idx + 1,
                ));
                continue;
            }
            if map.contains_key(agent) {
                errors.push(format!(
                    "entry #{}: duplicate agent {agent:?} (later entries would silently shadow)",
                    idx + 1,
                ));
                continue;
            }
            map.insert(agent.to_string(), token.to_string());
        }
        if !errors.is_empty() {
            return Err(format!(
                "agent_tokens has {} malformed entr{}: {}",
                errors.len(),
                if errors.len() == 1 { "y" } else { "ies" },
                errors.join("; "),
            ));
        }
        Ok(map)
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

    fn cfg_with_tokens(s: &str) -> GatewayConfig {
        GatewayConfig {
            agent_tokens: s.to_string(),
            ..GatewayConfig::default()
        }
    }

    #[test]
    fn parse_agent_tokens_empty_is_ok() {
        let cfg = cfg_with_tokens("");
        let m = cfg.parse_agent_tokens().expect("empty parses");
        assert!(m.is_empty());
    }

    #[test]
    fn parse_agent_tokens_happy_path() {
        let cfg = cfg_with_tokens("math:tok1, greeter: tok2 ");
        let m = cfg.parse_agent_tokens().expect("parses");
        assert_eq!(m.get("math"), Some(&"tok1".to_string()));
        assert_eq!(m.get("greeter"), Some(&"tok2".to_string()));
    }

    #[test]
    fn parse_agent_tokens_missing_colon_errors() {
        let cfg = cfg_with_tokens("math:tok1,malformed");
        let err = cfg.parse_agent_tokens().expect_err("must reject");
        assert!(
            err.contains("missing `:`") && err.contains("malformed"),
            "error should name the bad entry: {err}",
        );
    }

    #[test]
    fn parse_agent_tokens_empty_token_errors() {
        let cfg = cfg_with_tokens("math:tok1,greeter:");
        let err = cfg.parse_agent_tokens().expect_err("must reject");
        assert!(
            err.contains("empty token") && err.contains("greeter"),
            "error should name the offending agent: {err}",
        );
    }

    #[test]
    fn parse_agent_tokens_empty_agent_errors() {
        let cfg = cfg_with_tokens(":tok1");
        let err = cfg.parse_agent_tokens().expect_err("must reject");
        assert!(err.contains("empty agent name"), "got: {err}");
    }

    #[test]
    fn parse_agent_tokens_duplicate_agent_errors() {
        // Without this guard, a typo'd manifest could shadow the
        // first entry silently and you'd never know which token
        // is live for the agent.
        let cfg = cfg_with_tokens("math:tok1,math:tok2");
        let err = cfg.parse_agent_tokens().expect_err("must reject");
        assert!(
            err.contains("duplicate") && err.contains("math"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_agent_tokens_aggregates_multiple_errors() {
        // Operator deserves a complete diagnosis on one pass, not
        // a "fix one, re-run, see the next one" loop.
        let cfg = cfg_with_tokens("math:tok1,bad,:tok,greeter:");
        let err = cfg.parse_agent_tokens().expect_err("must reject");
        assert!(err.contains("3 malformed entries"), "got: {err}");
        assert!(err.contains("missing `:`"), "got: {err}");
        assert!(err.contains("empty agent name"), "got: {err}");
        assert!(err.contains("empty token"), "got: {err}");
    }
}
