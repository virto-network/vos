//! A node behind the gateway: its key, and its API, over its unix socket
//! (a few multiplexed connections) or QUIC (a stream a request) as the
//! gateway's key, which the node lists in its `gateways`. A dial never
//! holds the lock on the connections kept, and a node whose dial failed
//! counts as down for a backoff, so a dead node delays only the requests
//! that must go to it.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

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
    /// Held across a dial, so one dial is under way at a time: the
    /// connections' locks never are, and a request with a connection open
    /// never waits on a dial.
    one_dial: tokio::sync::Mutex<()>,
    /// Since when a dial is under way, if one is.
    dials: std::sync::Mutex<Option<Instant>>,
    /// After a failed dial, until when the node counts as down, and the
    /// backoff the next failure doubles.
    down: std::sync::Mutex<Down>,
}

/// A dial under way, marked while it lives: cleared however its holder
/// ends.
struct Dialing<'a>(&'a std::sync::Mutex<Option<Instant>>);

impl<'a> Dialing<'a> {
    fn mark(dials: &'a std::sync::Mutex<Option<Instant>>) -> Self {
        *dials.lock().expect("the dial mark") = Some(Instant::now());
        Self(dials)
    }
}

impl Drop for Dialing<'_> {
    fn drop(&mut self) {
        *self.0.lock().expect("the dial mark") = None;
    }
}

/// A dial under way longer than this, with no connection open, makes a
/// node not ready: reads go elsewhere while it lasts.
const SLOW_DIAL: Duration = Duration::from_millis(250);

#[derive(Default)]
struct Down {
    until: Option<Instant>,
    backoff: Duration,
}

/// The first backoff after a failed dial, and the longest.
const BACKOFF: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(8));

impl Upstream {
    pub fn new(key: [u8; 32], address: Address, secret: [u8; 32]) -> Arc<Self> {
        Arc::new(Self {
            key,
            address,
            secret,
            sockets: Mutex::new(Vec::new()),
            turn: AtomicUsize::new(0),
            quic: Mutex::new(None),
            one_dial: tokio::sync::Mutex::new(()),
            dials: std::sync::Mutex::new(None),
            down: std::sync::Mutex::new(Down::default()),
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
                        // Only this connection: one dialed since stays.
                        let mut kept = self.quic.lock().await;
                        if kept
                            .as_ref()
                            .is_some_and(|(_, kept)| kept.stable_id() == connection.stable_id())
                        {
                            *kept = None;
                        }
                    }
                    answered.map_err(|error| Unanswered(error.to_string()))
                }
            }
        };
        tokio::time::timeout(ANSWER, asked)
            .await
            .unwrap_or_else(|_| Err(Unanswered("no answer in time".into())))
    }

    /// Whether a read may go here now: the node is not down, and a
    /// connection is open or no dial has been under way for long. A read
    /// skips a node that is not, while another is.
    pub fn ready(&self) -> bool {
        if self.is_down() {
            return false;
        }
        if self
            .dialing_since()
            .is_none_or(|since| since.elapsed() <= SLOW_DIAL)
        {
            return true;
        }
        match &self.address {
            Address::Socket(_) => self
                .sockets
                .try_lock()
                .is_ok_and(|sockets| sockets.iter().any(|client| !client.is_closed())),
            Address::Quic(_) => self.quic.try_lock().is_ok_and(|kept| {
                kept.as_ref()
                    .is_some_and(|(_, connection)| connection.close_reason().is_none())
            }),
        }
    }

    fn dialing_since(&self) -> Option<Instant> {
        *self.dials.lock().expect("the dial mark")
    }

    fn is_down(&self) -> bool {
        let down = self.down.lock().expect("the down mark");
        down.until.is_some_and(|until| Instant::now() < until)
    }

    /// `dial`'s connection, made outside the connections' locks and one at
    /// a time; a node down after a failed dial is answered at once until
    /// its backoff passes.
    async fn dial<T>(
        &self,
        what: &str,
        dial: impl Future<Output = Result<T, Unanswered>>,
    ) -> Result<T, Unanswered> {
        let _turn = self.one_dial.lock().await;
        if self.is_down() {
            return Err(Unanswered(format!("{what}: down after a failed dial")));
        }
        let dialed = {
            let _dialing = Dialing::mark(&self.dials);
            dial.await
        };
        let mut down = self.down.lock().expect("the down mark");
        match &dialed {
            Ok(_) => *down = Down::default(),
            Err(_) => {
                down.backoff = (down.backoff * 2).clamp(BACKOFF.0, BACKOFF.1);
                down.until = Some(Instant::now() + down.backoff);
            }
        }
        dialed
    }

    /// A socket connection, in turn among those kept; a closed one
    /// replaced.
    async fn socket(&self, path: &PathBuf) -> Result<Multiplexed, Unanswered> {
        let kept = |sockets: &mut Vec<Multiplexed>| {
            sockets.retain(|client| !client.is_closed());
            let at = self.turn.fetch_add(1, Ordering::Relaxed);
            (!sockets.is_empty()).then(|| sockets[at % sockets.len()].clone())
        };
        {
            let mut sockets = self.sockets.lock().await;
            let open = kept(&mut sockets);
            // Past the connections kept, or while another dials, one open
            // serves.
            if let Some(client) = &open
                && (sockets.len() >= SOCKET_CONNECTIONS || self.dialing_since().is_some())
            {
                return Ok(client.clone());
            }
        }
        let dialed = self
            .dial(&path.display().to_string(), async {
                let stream = tokio::time::timeout(DIAL, tokio::net::UnixStream::connect(path))
                    .await
                    .map_err(|_| Unanswered(format!("{}: no connection in time", path.display())))?
                    .map_err(|error| Unanswered(format!("{}: {error}", path.display())))?;
                let (reading, writing) = stream.into_split();
                let (client, reader) = multiplexed(reading.compat(), writing.compat_write());
                tokio::spawn(reader);
                Ok(client)
            })
            .await;
        let mut sockets = self.sockets.lock().await;
        match dialed {
            Ok(client) => {
                if sockets.len() < SOCKET_CONNECTIONS {
                    sockets.push(client.clone());
                }
                Ok(client)
            }
            // Another task's connection, dialed meanwhile, serves.
            Err(error) => kept(&mut sockets).ok_or(error),
        }
    }

    /// The QUIC connection, dialed if none is open.
    async fn connection(&self, authority: &str) -> Result<quinn::Connection, Unanswered> {
        let open = |kept: &Option<(quinn::Endpoint, quinn::Connection)>| {
            kept.as_ref()
                .filter(|(_, connection)| connection.close_reason().is_none())
                .map(|(_, connection)| connection.clone())
        };
        if let Some(connection) = open(&*self.quic.lock().await) {
            return Ok(connection);
        }
        let dialed = self
            .dial(authority, async {
                // Dialed by the task before this one, while it waited.
                if let Some(connection) = open(&*self.quic.lock().await) {
                    return Ok((None, connection));
                }
                let (endpoint, connection) = self.handshake(authority).await?;
                Ok((Some(endpoint), connection))
            })
            .await?;
        match dialed {
            (Some(endpoint), connection) => {
                *self.quic.lock().await = Some((endpoint, connection.clone()));
                Ok(connection)
            }
            (None, connection) => Ok(connection),
        }
    }

    /// A QUIC connection to the node at `authority`, its key pinned.
    async fn handshake(
        &self,
        authority: &str,
    ) -> Result<(quinn::Endpoint, quinn::Connection), Unanswered> {
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
        Ok((endpoint, connection))
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
