//! HTTP types — the ingress speaks the standard `http` crate's
//! `Request`/`Response`, with an owned `Vec<u8>` body.
//!
//! Hyper fills a [`Request`] from the bounded connection body, the router
//! produces a [`Response`], and the server writes it back to the connection.
//!
//! `http::Response` is a foreign type, so the response constructors live
//! here as free functions rather than inherent methods.

use http::header::CONTENT_TYPE;
use http::{HeaderValue, StatusCode};

/// A parsed HTTP request with an owned byte body.
pub(crate) type Request = http::Request<Vec<u8>>;

/// An HTTP response with an owned byte body.
pub(crate) type Response = http::Response<Vec<u8>>;

/// `application/json` response with the given status + body.
pub(crate) fn json(status: u16, body: Vec<u8>) -> Response {
    build(status, "application/json", body)
}

/// Plain-text response with a non-default Content-Type. Used by
/// `/__metrics` to emit `text/plain; version=0.0.4` — Prometheus's
/// convention. `content_type` must be `'static` (it's interned as a
/// `HeaderValue::from_static`).
pub(crate) fn with_content_type(
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
) -> Response {
    build(status, content_type, body)
}

/// `text/plain` response carrying `msg` as the body.
pub(crate) fn text(status: u16, msg: impl Into<String>) -> Response {
    build(status, "text/plain", msg.into().into_bytes())
}

/// Build a response with a single Content-Type header. The status codes
/// the ingress emits are all valid, so `from_u16` never fails here.
fn build(status: u16, content_type: &'static str, body: Vec<u8>) -> Response {
    let mut resp = Response::new(body);
    *resp.status_mut() = StatusCode::from_u16(status).expect("ingress emits valid status codes");
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp
}

/// Shared error type for the HTTP/codec helpers — distinct from the
/// `Result` alias `#[messages]` emits.
pub(crate) type IoResult<T> = core::result::Result<T, String>;
