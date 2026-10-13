//! A node's ingress as a client reaches it: its address, and how the
//! client trusts it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use rustls::pki_types::ServerName;

use super::ClientError;
use crate::tls::{self, Trust};

/// A node's ingress, and how this client trusts it.
#[derive(Clone)]
pub struct Target {
    /// The `host:port` to connect to, which is also the `Host` header.
    pub(super) authority: String,
    /// Where a plain target connects: loopback addresses, never a name a
    /// resolver could answer for.
    pub(super) loopback: Option<Vec<SocketAddr>>,
    pub(super) tls: Option<(Arc<rustls::ClientConfig>, ServerName<'static>)>,
    /// The node's key, when pinned.
    pub(super) key: Option<[u8; 32]>,
    /// How the client trusts it, which the nodes it is sent on to inherit.
    pub(super) trust: Trust,
}

impl Target {
    /// The `host:port` it connects to.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The TLS a connection to it speaks, and the name it presents, for a
    /// caller with its own connections; none for plain HTTP.
    pub fn tls(&self) -> Option<(Arc<rustls::ClientConfig>, ServerName<'static>)> {
        self.tls.clone()
    }

    /// The node at `url` (`http://` or `https://`, then a host and an
    /// optional port), trusted as `trust` says. Plain HTTP reaches
    /// loopback addresses only, and HTTPS needs a key or a CA to trust.
    pub fn new(url: &str, trust: Trust) -> Result<Self, ClientError> {
        let invalid = |why: &str| ClientError::Http(format!("{url}: {why}"));
        let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(invalid("not an http:// or https:// address"));
        };
        let (host, port) = host_and_port(rest, secure).map_err(invalid)?;
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let mut loopback = None;
        let tls = match (secure, &trust) {
            (false, Trust::Loopback) => {
                let addresses: Vec<IpAddr> = if bare == "localhost" {
                    vec![Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()]
                } else {
                    match bare.parse::<IpAddr>() {
                        Ok(address) if address.is_loopback() => vec![address],
                        _ => return Err(invalid("plain HTTP reaches loopback addresses only")),
                    }
                };
                loopback = Some(
                    addresses
                        .into_iter()
                        .map(|address| SocketAddr::new(address, port))
                        .collect(),
                );
                None
            }
            (false, _) => return Err(invalid("a key or a CA to trust needs https://")),
            (true, Trust::Loopback) => {
                return Err(invalid("https:// needs a key or a CA to trust"));
            }
            (true, trust) => {
                let config = tls::client_config(trust)
                    .map_err(ClientError::Http)?
                    .expect("TLS for a key or a CA");
                let name = match (ServerName::try_from(bare.to_string()), trust) {
                    (Ok(name), _) => name,
                    // A pinned key does not need the name, which only
                    // goes in the handshake.
                    (Err(_), Trust::NodeKey(_)) => ServerName::try_from("node.vos")
                        .expect("a host name")
                        .to_owned(),
                    (Err(_), _) => return Err(invalid("not a host name or an address")),
                };
                Some((config, name))
            }
        };
        Ok(Self {
            authority: format!("{host}:{port}"),
            loopback,
            tls,
            key: match trust {
                Trust::NodeKey(key) => Some(key),
                _ => None,
            },
            trust,
        })
    }

    /// The node at `url`, over plain HTTP on a loopback address.
    pub fn loopback(url: &str) -> Result<Self, ClientError> {
        Self::new(url, Trust::Loopback)
    }
}

/// The host and port of an address's authority (`rest`, after its
/// scheme), the scheme's port when it gives none.
fn host_and_port(rest: &str, secure: bool) -> Result<(&str, u16), &'static str> {
    let authority = rest.trim_end_matches('/');
    if authority.is_empty() || authority.contains('/') {
        return Err("a host and a port, with no path");
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.contains(']') => {
            Ok((host, port.parse::<u16>().map_err(|_| "not a port")?))
        }
        _ => Ok((authority, if secure { 443 } else { 80 })),
    }
}

/// `host:port` for an `http://` or `https://` address, as a target holds
/// it.
pub(super) fn authority(url: &str) -> Option<String> {
    let (secure, rest) = match url.split_once("://")? {
        ("https", rest) => (true, rest),
        ("http", rest) => (false, rest),
        _ => return None,
    };
    let (host, port) = host_and_port(rest, secure).ok()?;
    Some(format!("{host}:{port}"))
}

#[cfg(test)]
mod tests {
    use super::authority;

    /// A replica's address matches the target made from it, the scheme's
    /// port written or not.
    #[test]
    fn an_address_s_authority_is_its_host_and_port() {
        assert_eq!(
            authority("https://n1.example").as_deref(),
            Some("n1.example:443")
        );
        assert_eq!(
            authority("https://n1.example/").as_deref(),
            Some("n1.example:443")
        );
        assert_eq!(
            authority("http://127.0.0.1:7700").as_deref(),
            Some("127.0.0.1:7700")
        );
        assert_eq!(authority("http://[::1]").as_deref(), Some("[::1]:80"));
        assert_eq!(authority("ftp://n1.example"), None);
        assert_eq!(authority("https://n1.example/path"), None);
    }
}
