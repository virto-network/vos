//! A request and its answer as VOS's HTTP front reads and writes them, and
//! the bounds on a head.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The most a request's or an answer's head may hold.
pub const MAX_HEAD: usize = 16 << 10;

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
    /// Where the connection came from.
    pub peer: Option<SocketAddr>,
    /// The body's place among the large bodies the server holds at once,
    /// if it is large: given back when dropped, so a handler done with
    /// the body may give it back before it answers.
    pub large: Option<Large>,
}

/// A large body's place: see [`Request::large`].
pub struct Large {
    pub(crate) _place: Slot,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_slice())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    /// 404, with no body.
    pub fn not_found() -> Self {
        Self::new(404, Vec::new())
    }
}

/// A `Content-Length` header's value, if it is a length.
pub fn content_length(value: &[u8]) -> Option<usize> {
    std::str::from_utf8(value).ok()?.trim().parse().ok()
}

/// A place among those counted (connections, or large bodies), given back
/// when its holder ends, however it ends: a handler's panic, or a cancel,
/// too.
pub(crate) struct Slot(Arc<AtomicUsize>);

impl Slot {
    /// A place among `open`, if fewer than `most` hold one.
    #[cfg(feature = "server")]
    pub(crate) fn take(open: &Arc<AtomicUsize>, most: usize) -> Option<Self> {
        open.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
            (held < most).then_some(held + 1)
        })
        .ok()
        .map(|_| Slot(Arc::clone(open)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
