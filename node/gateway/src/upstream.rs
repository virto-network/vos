//! A node behind the gateway: its key, and its API, over its unix socket
//! (a few multiplexed connections) or QUIC (a stream a request) as the
//! gateway's key, which the node lists in its `gateways`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Mutex;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use vos_api::client::{Answer, Multiplexed, multiplexed};

/// Socket connections the gateway keeps to a co-located node.
const SOCKET_CONNECTIONS: usize = 4;
/// How long a dial may take.
const DIAL: Duration = Duration::from_secs(10);
/// How long a request's answer may take: an install prepares a program.
const ANSWER: Duration = Duration::from_secs(300);

/// Where a node's API is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Address {
    /// `unix:/path`: its socket, for a node on the gateway's host.
    Socket(PathBuf),
    /// `quic://host:port`: its QUIC endpoint.
    Quic(String),
}

impl Address {
    pub fn parse(text: &str) -> Result<Self, String> {
        if let Some(path) = text.strip_prefix("unix:") {
            return Ok(Address::Socket(PathBuf::from(path)));
        }
        match text.strip_prefix("quic://") {
            Some(authority) if authority.rsplit_once(':').is_some() => {
                Ok(Address::Quic(authority.trim_end_matches('/').to_string()))
            }
            _ => Err(format!(
                "{text}: not a unix:/path or quic://host:port address"
            )),
        }
    }
}

/// Why a node gave no answer.
#[derive(Debug)]
pub struct Unanswered(pub String);

impl std::fmt::Display for Unanswered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unanswered {}

/// One node behind the gateway.
pub struct Upstream {
    /// The node's key, which a redirect names it by.
    pub key: [u8; 32],
    pub address: Address,
    /// The gateway's seed, its QUIC key.
    secret: [u8; 32],
    sockets: Mutex<Vec<Multiplexed>>,
    turn: AtomicUsize,
    quic: Mutex<Option<(quinn::Endpoint, quinn::Connection)>>,
}

impl Upstream {
    pub fn new(key: [u8; 32], address: Address, secret: [u8; 32]) -> Arc<Self> {
        Arc::new(Self {
            key,
            address,
            secret,
            sockets: Mutex::new(Vec::new()),
            turn: AtomicUsize::new(0),
            quic: Mutex::new(None),
        })
    }

    /// A request of `kind` holding `body`: the answer frame's kind and
    /// body. Sent once: a request whose node failed mid-way may have run,
    /// so it is answered unavailable, never sent again.
    pub async fn request(&self, kind: u16, body: &[u8]) -> Result<Answer, Unanswered> {
        let asked = async {
            match &self.address {
                Address::Socket(path) => {
                    let client = self.socket(path).await?;
                    client
                        .request(kind, body)
                        .await
                        .map_err(|error| Unanswered(error.to_string()))
                }
                Address::Quic(authority) => {
                    let connection = self.connection(authority).await?;
                    let answered = vos_api::quic::request(&connection, kind, body).await;
                    if answered.is_err() {
                        *self.quic.lock().await = None;
                    }
                    answered.map_err(|error| Unanswered(error.to_string()))
                }
            }
        };
        tokio::time::timeout(ANSWER, asked)
            .await
            .unwrap_or_else(|_| Err(Unanswered("no answer in time".into())))
    }

    /// A socket connection, in turn among those kept; a closed one
    /// replaced.
    async fn socket(&self, path: &PathBuf) -> Result<Multiplexed, Unanswered> {
        let mut sockets = self.sockets.lock().await;
        sockets.retain(|client| !client.is_closed());
        if sockets.len() < SOCKET_CONNECTIONS {
            let stream = tokio::time::timeout(DIAL, tokio::net::UnixStream::connect(path))
                .await
                .map_err(|_| Unanswered(format!("{}: no connection in time", path.display())))?
                .map_err(|error| Unanswered(format!("{}: {error}", path.display())))?;
            let (reading, writing) = stream.into_split();
            let (client, reader) = multiplexed(reading.compat(), writing.compat_write());
            tokio::spawn(reader);
            sockets.push(client);
        }
        let at = self.turn.fetch_add(1, Ordering::Relaxed) % sockets.len();
        Ok(sockets[at].clone())
    }

    /// The QUIC connection, dialed if none is open.
    async fn connection(&self, authority: &str) -> Result<quinn::Connection, Unanswered> {
        let mut kept = self.quic.lock().await;
        if let Some((_, connection)) = kept.as_ref()
            && connection.close_reason().is_none()
        {
            return Ok(connection.clone());
        }
        let failed = |why: String| Unanswered(format!("{authority}: {why}"));
        let address: SocketAddr = tokio::net::lookup_host(authority)
            .await
            .map_err(|error| failed(error.to_string()))?
            .next()
            .ok_or_else(|| failed("no address".into()))?;
        let bind: SocketAddr = if address.is_ipv4() {
            "0.0.0.0:0".parse().expect("an address")
        } else {
            "[::]:0".parse().expect("an address")
        };
        let endpoint = quinn::Endpoint::client(bind).map_err(|error| failed(error.to_string()))?;
        let config = vos_net::api::client_config(
            &self.secret,
            self.key,
            Arc::new(quinn::TransportConfig::default()),
        );
        let connecting = endpoint
            .connect_with(config, address, "node.vos")
            .map_err(|error| failed(error.to_string()))?;
        let connection = tokio::time::timeout(DIAL, connecting)
            .await
            .map_err(|_| failed("no handshake in time".into()))?
            .map_err(|error| failed(error.to_string()))?;
        *kept = Some((endpoint, connection.clone()));
        Ok(connection)
    }
}

#[cfg(test)]
mod tests {
    use super::Address;

    #[test]
    fn addresses_are_a_socket_or_quic() {
        assert_eq!(
            Address::parse("unix:/run/vos/api.sock"),
            Ok(Address::Socket("/run/vos/api.sock".into()))
        );
        assert_eq!(
            Address::parse("quic://n1.example:7710"),
            Ok(Address::Quic("n1.example:7710".into()))
        );
        assert!(Address::parse("http://n1.example").is_err());
        assert!(Address::parse("quic://n1.example").is_err());
    }
}
