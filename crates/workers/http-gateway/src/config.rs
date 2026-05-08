//! Operator-controlled config, read from process env vars at runtime.
//!
//! Env-var keys:
//!
//! - `HTTP_GATEWAY_BIND_ADDR` — IP to bind both protocols. Default
//!   `127.0.0.1` (loopback only). Set to `0.0.0.0` for public bind.
//! - `HTTP_GATEWAY_ADMIN_TOKEN` — when set, the value of the
//!   `X-Admin-Token` request header must match (constant-time) for
//!   `/__admin/*` to respond. When unset, admin endpoints return 404
//!   so the gateway doesn't even acknowledge their existence.
//! - `HTTP_GATEWAY_AUTH_TOKEN` — when set, every non-admin request
//!   must carry `Authorization: Bearer <token>` (constant-time
//!   compared against the env value) or it's rejected with 401. When
//!   unset, dispatch is open and a startup warning is logged.

use std::env;
use std::net::{IpAddr, Ipv4Addr};

pub(crate) const ENV_BIND_ADDR: &str = "HTTP_GATEWAY_BIND_ADDR";
pub(crate) const ENV_ADMIN_TOKEN: &str = "HTTP_GATEWAY_ADMIN_TOKEN";
pub(crate) const ENV_AUTH_TOKEN: &str = "HTTP_GATEWAY_AUTH_TOKEN";
#[cfg(feature = "http3")]
pub(crate) const ENV_TLS_CERT: &str = "HTTP_GATEWAY_TLS_CERT";
#[cfg(feature = "http3")]
pub(crate) const ENV_TLS_KEY: &str = "HTTP_GATEWAY_TLS_KEY";

const DEFAULT_BIND: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Parse the bind IP from `HTTP_GATEWAY_BIND_ADDR`; safe default
/// `127.0.0.1` so a bare deployment never accidentally binds public.
pub(crate) fn bind_ip() -> IpAddr {
    env::var(ENV_BIND_ADDR)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BIND)
}

pub(crate) fn admin_token() -> Option<String> {
    env::var(ENV_ADMIN_TOKEN).ok().filter(|s| !s.is_empty())
}

pub(crate) fn auth_token() -> Option<String> {
    env::var(ENV_AUTH_TOKEN).ok().filter(|s| !s.is_empty())
}

/// Both PEM paths for TLS — `(cert_chain_path, key_path)`. Returns
/// `None` if either is unset/empty so callers fall back to a
/// self-signed cert.
#[cfg(feature = "http3")]
pub(crate) fn tls_paths() -> Option<(String, String)> {
    let cert = env::var(ENV_TLS_CERT).ok().filter(|s| !s.is_empty())?;
    let key = env::var(ENV_TLS_KEY).ok().filter(|s| !s.is_empty())?;
    Some((cert, key))
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
pub(crate) fn header_value<'a>(
    headers: &'a [(String, String)],
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}
