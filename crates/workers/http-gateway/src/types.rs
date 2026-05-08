//! Cross-protocol HTTP types.
//!
//! `Request` and `Response` decouple the actor-side routing from the
//! wire-side details — hyper, h3, and any future transport all
//! parse into `Request` and serialize back from `Response`. `Job` is
//! the mpsc envelope that ferries a `Request` from a connection task
//! to the actor handler and the `Response` back.

use tokio::sync::oneshot;

/// One HTTP exchange in flight. Connection task pushes onto the
/// actor's mpsc; the actor handler fills `resp_tx` once `ctx.ask`
/// completes; the task awaits the oneshot and writes the response.
pub(crate) struct Job {
    pub(crate) request: Request,
    pub(crate) resp_tx: oneshot::Sender<Response>,
}

pub(crate) struct Request {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) query: String,
    /// Lower-case header names paired with their values. Capped at
    /// `limits::MAX_REQUEST_HEADERS` by the wire-side parser.
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) content_type: &'static str,
    pub(crate) body: Vec<u8>,
}

impl Response {
    pub(crate) fn json(status: u16, body: Vec<u8>) -> Self {
        Self { status, content_type: "application/json", body }
    }

    pub(crate) fn text(status: u16, msg: impl Into<String>) -> Self {
        Self { status, content_type: "text/plain", body: msg.into().into_bytes() }
    }

    pub(crate) fn empty(status: u16) -> Self {
        Self { status, content_type: "text/plain", body: Vec::new() }
    }
}

/// Shared error type for the HTTP/codec helpers — distinct from the
/// `Result` alias `#[messages]` emits.
pub(crate) type IoResult<T> = core::result::Result<T, String>;
