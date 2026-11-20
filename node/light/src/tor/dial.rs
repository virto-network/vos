//! What the client dials through: arti for an onion, TCP for a gateway's
//! clearnet port ([`super::Tor`]), or a test's in-process gateway.

use std::future::Future;
use std::io;
use std::pin::Pin;

use arti_client::IsolationToken;
use tokio::io::{AsyncRead, AsyncWrite};

/// A byte stream to a gateway.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// A dialed stream.
pub type Stream = Box<dyn Io>;

/// Where a stream goes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// A port of an onion service, by its `.onion` address.
    Onion { address: String, port: u16 },
    /// A gateway's clearnet port: no circuit, the device's address seen.
    Clearnet { host: String, port: u16 },
}

/// The circuit a connection's stream takes: an arti isolation token drawn
/// for that connection alone, which no other stream's is compatible with,
/// so arti shares its circuit with none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Circuit(IsolationToken);

impl Circuit {
    /// A circuit no stream has taken.
    pub fn new() -> Self {
        Self(IsolationToken::new())
    }

    /// Its isolation token.
    pub fn token(self) -> IsolationToken {
        self.0
    }
}

impl Default for Circuit {
    fn default() -> Self {
        Self::new()
    }
}

/// The future of a dial.
pub type Dialing = Pin<Box<dyn Future<Output = io::Result<Stream>> + Send>>;

/// A dial's failure to find an onion service, or to reach it through its
/// introduction points (arti's `OnionServiceNotFound`,
/// `OnionServiceNotRunning`, `OnionServiceConnectionFailed`): a service
/// just launched or relaunched is not published yet, and every attempt in
/// a burst fails alike, where one a few seconds on often succeeds.
#[derive(Debug)]
pub struct Unpublished(pub String);

impl std::fmt::Display for Unpublished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Unpublished {}

impl Unpublished {
    /// The dial's error for it.
    pub fn error(why: impl Into<String>) -> io::Error {
        io::Error::other(Self(why.into()))
    }

    /// Whether `error` is one.
    pub fn is(error: &io::Error) -> bool {
        error
            .get_ref()
            .is_some_and(|inner| inner.downcast_ref::<Self>().is_some())
    }
}

/// A way to open streams to gateways.
pub trait Dial: Send + Sync + 'static {
    /// A stream to `target` on `circuit`, which a clearnet target ignores.
    fn dial(&self, target: &Target, circuit: Circuit) -> Dialing;

    /// Dormant (no circuit kept, no timer firing) or awake.
    fn set_dormant(&self, _dormant: bool) {}
}
