//! One node's API over QUIC: one connection, dialed on first use and again
//! once closed, a stream a request, each within its deadline, the node's
//! stream limit holding the rest back.

use std::cell::{Cell, RefCell};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use smol::Timer;
use vos_api::{FRAME_ERROR, FrameError, Kind};
use vos_wire::ids::AgentId;
use vos_wire::ingress::Response;
use vos_wire::{Decode, Encode};

/// How long a connection may take to open, its handshake included.
const CONNECT: Duration = Duration::from_secs(10);

/// What a pool saw over an interval: the most requests in flight at once
/// on its connection.
#[derive(Clone, Default)]
pub struct PoolStats {
    pub in_use_max: usize,
}

impl PoolStats {
    pub fn absorb(&mut self, other: &PoolStats) {
        self.in_use_max = self.in_use_max.max(other.in_use_max);
    }
}

/// A node's API over QUIC: its address, the node's key it pins, the
/// driver's key it presents, and the connection once dialed.
pub struct Pool {
    /// The `host:port` it dials, which a redirect's contact names.
    pub authority: String,
    node: [u8; 32],
    client: [u8; 32],
    dialed: smol::lock::Mutex<Option<(quinn::Endpoint, quinn::Connection)>>,
    in_use: Cell<usize>,
    stats: RefCell<PoolStats>,
}

impl Pool {
    /// The node API at `url` (`quic://host:port`), pinned to the node's
    /// key `node`, as the driver's key `client`.
    pub fn quic(url: &str, node: [u8; 32], client: [u8; 32]) -> Result<Self, String> {
        let authority = url
            .strip_prefix("quic://")
            .ok_or_else(|| format!("{url}: not a quic:// address"))?
            .to_string();
        Ok(Self {
            authority,
            node,
            client,
            dialed: smol::lock::Mutex::new(None),
            in_use: Cell::new(0),
            stats: RefCell::new(PoolStats::default()),
        })
    }

    /// The connection, dialed if none is open.
    async fn connection(&self) -> Result<quinn::Connection, String> {
        let mut dialed = self.dialed.lock().await;
        if let Some((_, connection)) = dialed.as_ref()
            && connection.close_reason().is_none()
        {
            return Ok(connection.clone());
        }
        let address = self
            .authority
            .to_socket_addrs()
            .map_err(|error| error.to_string())?
            .next()
            .ok_or("the node has no address")?;
        let bind: SocketAddr = if address.is_ipv4() {
            "0.0.0.0:0".parse().expect("an address")
        } else {
            "[::]:0".parse().expect("an address")
        };
        let socket = std::net::UdpSocket::bind(bind).map_err(|error| error.to_string())?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::SmolRuntime),
        )
        .map_err(|error| error.to_string())?;
        let config = vos_net::api::client_config(
            &self.client,
            self.node,
            Arc::new(quinn::TransportConfig::default()),
        );
        let connecting = endpoint
            .connect_with(config, address, "node.vos")
            .map_err(|error| error.to_string())?;
        let late = async {
            Timer::after(CONNECT).await;
            Err(quinn::ConnectionError::TimedOut)
        };
        let connection = smol::future::or(connecting, late)
            .await
            .map_err(|error| error.to_string())?;
        *dialed = Some((endpoint, connection.clone()));
        Ok(connection)
    }

    /// What it saw since the last time asked.
    pub fn take_stats(&self) -> PoolStats {
        std::mem::take(&mut *self.stats.borrow_mut())
    }

    /// Open the connection: a handshake done before the load starts.
    pub async fn warm(&self) {
        let _ = self.connection().await;
    }

    /// A request of `kind` for `agent` holding `body`: the node's answer,
    /// within `within`. An error is the transport's: no answer came.
    pub async fn post(
        &self,
        kind: Kind,
        agent: AgentId,
        body: &[u8],
        within: Duration,
    ) -> Result<Response, String> {
        let mut framed = agent.0.encode();
        framed.extend_from_slice(body);
        let asked = async {
            let connection = self.connection().await?;
            let _in_flight = InFlight::new(self);
            vos_api::quic::request(&connection, kind as u16, vos_api::Mark::Unmarked, &framed)
                .await
                .map_err(|error| error.to_string())
        };
        let late = async {
            Timer::after(within).await;
            Err("timed out".to_string())
        };
        let (answered, bytes) = smol::future::or(asked, late).await?;
        if answered == FRAME_ERROR {
            return Err(match FrameError::decode_exact(&bytes) {
                Some(error) => format!("{error:?}"),
                None => "an unreadable frame error".into(),
            });
        }
        Response::decode(&bytes)
            .map(|(response, _)| response)
            .map_err(|_| "an answer it cannot read".to_string())
    }
}

/// A request in flight on a pool's connection, counted until it ends or
/// is dropped past its deadline.
struct InFlight<'a>(&'a Pool);

impl<'a> InFlight<'a> {
    fn new(pool: &'a Pool) -> Self {
        pool.in_use.set(pool.in_use.get() + 1);
        let mut stats = pool.stats.borrow_mut();
        stats.in_use_max = stats.in_use_max.max(pool.in_use.get());
        Self(pool)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.in_use.set(self.0.in_use.get() - 1);
    }
}

#[cfg(test)]
mod tests;
