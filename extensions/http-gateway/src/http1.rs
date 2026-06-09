//! HTTP/1.1 wire codec.
//!
//! In transport mode the host hands the gateway a plaintext byte stream
//! (`ctx.read` / `ctx.write`); this module turns a growing read buffer
//! into an [`http::Request`] and a
//! [`Response`] back into bytes. The request **head** (request line +
//! headers) is parsed by [`httparse`] — a zero-alloc parser;
//! we copy its output into an `http::Request` and own only the
//! framing decisions on top of it (body length, keep-alive,
//! Content-Length / Transfer-Encoding policy) and the response
//! serializer. Everything here is **pure** (no `ctx`, no I/O) so it
//! unit-tests directly; the read/write loop that drives it lives in
//! `lib.rs`'s `handle_connection`.
//!
//! ## Scope (deliberately small)
//!
//! - **Supported:** request line + case-insensitive headers,
//!   `Content-Length`-framed bodies, **keep-alive** (HTTP/1.1 default;
//!   `Connection: close` opts out; HTTP/1.0 default-close unless
//!   `Connection: keep-alive`), the `MAX_*` limits in [`crate::limits`],
//!   and pipelined requests served one-at-a-time (leftover bytes stay in
//!   the caller's buffer).
//! - **Rejected explicitly:** chunked / any `Transfer-Encoding` request
//!   body → `411` (we frame by `Content-Length` only; this also rules
//!   out trailers). An over-long head → `431`, an over-long body → `413`.
//! - **Not acted on (safe to ignore — they don't affect framing):**
//!   `Expect: 100-continue`, `Upgrade`/websockets, HTTP/2 h2c. The body
//!   is still framed correctly by `Content-Length`.

use http::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use http::{Request, Version};

use crate::limits::{MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_REQUEST_HEADERS};
use crate::types::{Response, text};

/// Outcome of trying to parse a request **head** (request line + headers
/// up to the blank-line terminator) out of the current read buffer.
pub(crate) enum HeadOutcome {
    /// A full head was parsed. The caller now reads
    /// `head_len + content_length` total bytes before extracting the body.
    Complete(ParsedHead),
    /// The terminator hasn't arrived yet — read more and retry.
    NeedMore,
    /// Protocol error — write this response and close the connection.
    Error(Response),
}

/// A parsed request head + the framing facts the caller needs to pull
/// the body out of the buffer.
pub(crate) struct ParsedHead {
    /// The request line + headers as an `http::Request` with an empty
    /// body — the caller fills the body via [`Request::map`] once it has
    /// read `content_length` bytes.
    pub(crate) request: Request<()>,
    /// Bytes occupied by the head, **including** the `\r\n\r\n`
    /// terminator — the body starts at this offset in the buffer.
    pub(crate) head_len: usize,
    /// Body length from `Content-Length` (0 when absent).
    pub(crate) content_length: usize,
    /// Whether to keep the connection open after this exchange.
    pub(crate) keep_alive: bool,
}

/// Parse a request head out of `buf` with [`httparse`], copying it into
/// an [`http::Request`]. Pure: it never consumes `buf` — the caller
/// drains `head_len + content_length` bytes once the whole request has
/// arrived. Returns [`HeadOutcome::NeedMore`] until httparse can read a
/// full head (`\r\n\r\n`). On top of httparse's request-line + header
/// parse we own the framing policy: reject any `Transfer-Encoding` (411)
/// / duplicate `Content-Length` (400), bound the body (413) and the head
/// (431), and decide keep-alive.
pub(crate) fn parse_head(buf: &[u8]) -> HeadOutcome {
    let mut raw_headers = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
    let mut req = httparse::Request::new(&mut raw_headers);
    let head_len = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            // Head not fully buffered yet. Bound how much we'll hold while
            // waiting for the terminator (slow-loris / header flood).
            if buf.len() > MAX_HEADER_BYTES {
                return HeadOutcome::Error(text(431, "request head too large"));
            }
            return HeadOutcome::NeedMore;
        }
        Err(httparse::Error::TooManyHeaders) => {
            return HeadOutcome::Error(text(431, "too many request headers"));
        }
        Err(_) => {
            return HeadOutcome::Error(text(400, "malformed request"));
        }
    };
    if head_len > MAX_HEADER_BYTES {
        return HeadOutcome::Error(text(431, "request head too large"));
    }

    // On `Complete`, httparse guarantees method/path/version are present.
    let method = req.method.unwrap_or_default();
    let target = req.path.unwrap_or_default();
    if method.is_empty() || target.is_empty() {
        return HeadOutcome::Error(text(400, "malformed request line"));
    }
    // `version` is the HTTP minor: 1 ⇒ HTTP/1.1 (keep-alive default), else
    // (HTTP/1.0) close-by-default.
    let version = if req.version == Some(1) {
        Version::HTTP_11
    } else {
        Version::HTTP_10
    };

    // Copy the parsed pieces into an `http::Request`. The builder
    // appends each header (so duplicates are preserved for the
    // multi-value checks below), and validates the method / URI / header
    // syntax — anything it rejects is a malformed request → 400.
    let mut builder = Request::builder()
        .method(method)
        .uri(target)
        .version(version);
    for h in req.headers.iter() {
        builder = builder.header(h.name, h.value);
    }
    let request = match builder.body(()) {
        Ok(r) => r,
        Err(_) => return HeadOutcome::Error(text(400, "malformed request")),
    };
    let headers = request.headers();

    // We frame strictly by Content-Length; any Transfer-Encoding (the
    // only one being `chunked`) is rejected so we never misframe a body
    // — this also rules out trailers, which only ride chunked.
    if headers.contains_key(TRANSFER_ENCODING) {
        return HeadOutcome::Error(text(
            411,
            "chunked transfer-encoding is not supported; send Content-Length",
        ));
    }

    // RFC 7230 §3.3.3: a message with multiple Content-Length fields is
    // invalid. We frame by the first, so a second, larger one would leave
    // its surplus body to be re-parsed as the next pipelined request —
    // reject up front instead.
    if headers.get_all(CONTENT_LENGTH).iter().count() > 1 {
        return HeadOutcome::Error(text(400, "duplicate Content-Length"));
    }

    let content_length = match headers.get(CONTENT_LENGTH) {
        Some(v) => {
            // RFC 7230 §3.3.2: Content-Length is `1*DIGIT`. Reject anything
            // else up front — `usize::parse` would otherwise accept a leading
            // `+` (and `.trim()` would eat stray whitespace), the kind of
            // leniency that feeds request-smuggling desync with a sloppy proxy.
            let Ok(s) = v.to_str() else {
                return HeadOutcome::Error(text(400, "invalid Content-Length"));
            };
            let s = s.trim();
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return HeadOutcome::Error(text(400, "invalid Content-Length"));
            }
            match s.parse::<usize>() {
                Ok(n) => n,
                Err(_) => {
                    return HeadOutcome::Error(text(400, "invalid Content-Length"));
                }
            }
        }
        None => 0,
    };
    if content_length > MAX_BODY_BYTES {
        return HeadOutcome::Error(text(413, "request body too large"));
    }

    let close_requested = connection_has_token(&request, "close");
    let keep_alive = if version == Version::HTTP_11 {
        !close_requested
    } else {
        connection_has_token(&request, "keep-alive")
    };

    HeadOutcome::Complete(ParsedHead {
        request,
        head_len,
        content_length,
        keep_alive,
    })
}

/// `true` if any `Connection` header value carries `token` (case-
/// insensitively), tolerating both comma-lists in one header and
/// repeated `Connection` headers.
fn connection_has_token(request: &Request<()>, token: &str) -> bool {
    request
        .headers()
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| header_token_present(v, token))
}

/// Serialize a [`Response`] into HTTP/1.1 wire bytes. Always emits an
/// explicit `Content-Length` and `Connection` header so a keep-alive
/// peer can frame the reply and know whether to reuse the socket.
pub(crate) fn serialize_response(resp: &Response, keep_alive: bool) -> Vec<u8> {
    let status = resp.status();
    // The numeric code is what clients parse; the reason phrase is
    // advisory. `http` knows the canonical phrase for every code we emit.
    let reason = status.canonical_reason().unwrap_or("");
    let conn = if keep_alive { "keep-alive" } else { "close" };
    // Every response built via `crate::types` carries exactly one
    // Content-Type; default defensively if one is somehow absent.
    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let body = resp.body();
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
        status.as_u16(),
        reason,
        content_type,
        body.len(),
        conn,
    );
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    out
}

/// `true` if a comma-separated header value (e.g. `Connection:
/// keep-alive, Upgrade`) contains `token`, case-insensitively.
fn header_token_present(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::json;
    use http::Method;

    fn complete(buf: &[u8]) -> ParsedHead {
        match parse_head(buf) {
            HeadOutcome::Complete(h) => h,
            HeadOutcome::NeedMore => panic!("unexpected NeedMore"),
            HeadOutcome::Error(r) => panic!("unexpected Error {}: {:?}", r.status(), r.body()),
        }
    }

    fn err_status(buf: &[u8]) -> u16 {
        match parse_head(buf) {
            HeadOutcome::Error(r) => r.status().as_u16(),
            HeadOutcome::Complete(_) => panic!("expected Error, got Complete"),
            HeadOutcome::NeedMore => panic!("expected Error, got NeedMore"),
        }
    }

    #[test]
    fn parses_simple_get() {
        let h = complete(b"GET /counter/inc?x=1 HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(h.request.method(), Method::GET);
        assert_eq!(h.request.uri().path(), "/counter/inc");
        assert_eq!(h.request.uri().query(), Some("x=1"));
        assert_eq!(h.content_length, 0);
        assert!(h.keep_alive, "HTTP/1.1 defaults to keep-alive");
        assert_eq!(
            h.head_len,
            b"GET /counter/inc?x=1 HTTP/1.1\r\nHost: localhost\r\n\r\n".len()
        );
    }

    #[test]
    fn parses_post_with_body_framing() {
        let raw = b"POST /math/add HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"a\":2,\"b\":3}";
        let h = complete(raw);
        assert_eq!(h.request.method(), Method::POST);
        assert_eq!(h.request.uri().path(), "/math/add");
        assert_eq!(h.content_length, 13);
        // head_len points exactly past the blank line, at the body start.
        assert_eq!(
            &raw[h.head_len..h.head_len + h.content_length],
            b"{\"a\":2,\"b\":3}"
        );
    }

    #[test]
    fn need_more_until_terminator() {
        assert!(matches!(
            parse_head(b"GET / HTTP/1.1\r\nHost: x"),
            HeadOutcome::NeedMore
        ));
        assert!(matches!(parse_head(b""), HeadOutcome::NeedMore));
    }

    #[test]
    fn connection_close_disables_keepalive() {
        let h = complete(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n");
        assert!(!h.keep_alive);
        // Token inside a list is honoured too.
        let h = complete(b"GET / HTTP/1.1\r\nConnection: keep-alive, close\r\n\r\n");
        assert!(!h.keep_alive);
    }

    #[test]
    fn http10_defaults_to_close() {
        let h = complete(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n");
        assert!(!h.keep_alive);
        let h = complete(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
        assert!(h.keep_alive);
    }

    #[test]
    fn case_insensitive_header_lookup() {
        let h = complete(b"POST /x/y HTTP/1.1\r\nCONTENT-LENGTH: 4\r\n\r\nabcd");
        assert_eq!(h.content_length, 4);
    }

    #[test]
    fn chunked_is_411() {
        assert_eq!(
            err_status(b"POST /x/y HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
            411
        );
    }

    #[test]
    fn oversized_body_is_413() {
        let raw = format!(
            "POST /x/y HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert_eq!(err_status(raw.as_bytes()), 413);
    }

    #[test]
    fn malformed_request_line_is_400() {
        assert_eq!(err_status(b"GET\r\n\r\n"), 400);
        assert_eq!(err_status(b"GET /a b c HTTP/1.1\r\n\r\n"), 400);
        assert_eq!(err_status(b"GET /x HTTP/1.1 extra\r\n\r\n"), 400);
    }

    #[test]
    fn bad_content_length_is_400() {
        assert_eq!(
            err_status(b"POST /x/y HTTP/1.1\r\nContent-Length: abc\r\n\r\n"),
            400
        );
    }

    #[test]
    fn non_rfc_content_length_is_400() {
        // RFC 7230 §3.3.2 is `1*DIGIT`. `usize::parse` would otherwise accept a
        // leading `+`; reject it (and an internal-space value) so a lenient
        // framing can't desync against a stricter front proxy.
        assert_eq!(
            err_status(b"POST /x/y HTTP/1.1\r\nContent-Length: +5\r\n\r\nhello"),
            400
        );
        assert_eq!(
            err_status(b"POST /x/y HTTP/1.1\r\nContent-Length: 1 0\r\n\r\nhelloworld"),
            400
        );
    }

    #[test]
    fn duplicate_content_length_is_400() {
        // RFC 7230 §3.3.3 — conflicting Content-Length must be rejected, not
        // framed by the first (the surplus would re-parse as the next request).
        assert_eq!(
            err_status(b"POST /x/y HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 44\r\n\r\n"),
            400,
        );
    }

    #[test]
    fn too_many_headers_is_431() {
        let mut raw = String::from("GET / HTTP/1.1\r\n");
        for i in 0..(MAX_REQUEST_HEADERS + 1) {
            raw.push_str(&format!("X-H{i}: v\r\n"));
        }
        raw.push_str("\r\n");
        assert_eq!(err_status(raw.as_bytes()), 431);
    }

    #[test]
    fn serialize_round_trips_status_and_framing() {
        let resp = json(200, b"{\"ok\":true}".to_vec());
        let bytes = serialize_response(&resp, true);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.contains("Content-Length: 11\r\n"));
        assert!(text.contains("Connection: keep-alive\r\n"));
        assert!(text.ends_with("\r\n\r\n{\"ok\":true}"));
    }

    #[test]
    fn serialize_close_marks_connection_close() {
        let bytes = serialize_response(&text(404, "nope"), false);
        let body = String::from_utf8(bytes).unwrap();
        assert!(body.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(body.contains("Connection: close\r\n"));
    }
}
