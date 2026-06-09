//! Host I/O effect protocol.
//!
//! When a worker/WASM handler calls `ctx.ask()` / `ctx.fetch()` / etc.,
//! the future yields `Pending` with a serialized effect request in the
//! context's host_io slot. The host reads the request, fulfills it
//! (possibly asynchronously), writes the result back, and re-polls.
//!
//! All effect requests start with a single tag byte that identifies
//! the effect type, followed by a tag-specific payload.

use alloc::string::String;
use alloc::vec::Vec;

// ── Effect tags ─────────────────────────────────────────────────────

/// Send a message to another service. Synchronous request-reply.
/// Payload: `[target:u32 LE][message_bytes...]`
/// Result: rkyv-encoded `Value` (the reply); an empty result decodes
/// to `Value::Unit` — a dispatch failure (no route / panic / timeout)
/// is **indistinguishable** from a `()`-returning handler on this path.
pub const EFFECT_ASK: u8 = 0x01;

/// Like [`EFFECT_ASK`], but the response is **status-framed** so the
/// caller can tell a real reply from a dispatch failure (used by the
/// http-gateway's `ctx.ask_dispatch`). Payload is identical
/// (`[target:u32 LE][message_bytes...]`); the result leads with a
/// [`RESP_OK`]/[`RESP_ERR`] byte (same convention as the byte-stream
/// effects): `[RESP_OK][reply…]` on a `STATUS_DONE` envelope (reply may
/// be empty for a `()` return), `[RESP_ERR]` on any failure (no route /
/// non-DONE status / timeout). The host's transport `ConnFulfiller`
/// fulfils this; actor/service hosts don't.
pub const EFFECT_ASK_DISPATCH: u8 = 0x04;

/// HTTP request. Synchronous from the handler's perspective; the
/// host performs the request asynchronously and returns the response.
/// Payload: see `FetchRequest::encode`.
/// Result: see `FetchResponse::encode`.
pub const EFFECT_FETCH: u8 = 0x02;

/// Fetch a proof blob from the host's content-addressed store.
/// Payload: `[hash: 32 bytes]`.
/// Result: blob bytes when found, empty bytes when missing.
pub const EFFECT_BLOB_GET: u8 = 0x03;

// ── Byte-stream effects ──────────────────────────────────
//
// Raw TCP via the host reactor (`smol::Async` in `node.rs`). The host
// assigns opaque `u64` listener / connection ids. Each request is
// `[tag][body]`; each response leads with a status byte (`RESP_OK` /
// `RESP_ERR`) — on error the rest is a UTF-8 message. The `bytestream`
// module below has the encoders (Context side) + decoders (host side).
// These only do anything against the native extension host; WASM / PVM
// builds don't expose them.

/// Bind a TCP listener. Body `[tls: u8][addr: str]` (`tls = 1` → the host
/// wraps every accepted connection in its configured TLS acceptor, so the
/// extension reads/writes plaintext). Ok resp `[1][listener_id: u64]`.
pub const EFFECT_LISTEN: u8 = 0x10;
/// Accept one connection. Body `[listener_id: u64]`. Ok resp `[1][conn_id: u64]`.
pub const EFFECT_ACCEPT: u8 = 0x11;
/// Read up to `max` bytes. Body `[conn_id: u64][max: u32]`. Ok resp `[1][bytes…]`
/// (empty bytes = EOF / peer closed).
pub const EFFECT_READ: u8 = 0x12;
/// Write bytes. Body `[conn_id: u64][bytes…]`. Ok resp `[1][n: u32]` (bytes written).
pub const EFFECT_WRITE: u8 = 0x13;
/// Close a connection. Body `[conn_id: u64]`. Ok resp `[1]`. Idempotent.
pub const EFFECT_CLOSE: u8 = 0x14;

/// Response status byte: the op succeeded; the rest is the typed payload.
pub const RESP_OK: u8 = 1;
/// Response status byte: the op failed; the rest is a UTF-8 error message.
pub const RESP_ERR: u8 = 0;

/// Byte-stream effect wire codecs, shared by the extension `Context`
/// (encodes requests / decodes responses) and the host reactor
/// (decodes requests / encodes responses).
pub mod bytestream {
    use super::{
        Cursor, EFFECT_ACCEPT, EFFECT_CLOSE, EFFECT_LISTEN, EFFECT_READ, EFFECT_WRITE, RESP_ERR,
        RESP_OK, write_str, write_u32, write_u64,
    };
    use alloc::string::String;
    use alloc::vec::Vec;

    // ── Request encoders (extension `Context` side) ─────────────────

    /// Plaintext listener.
    pub fn encode_listen(addr: &str) -> Vec<u8> {
        encode_listen_inner(addr, false)
    }
    /// TLS listener — the host terminates TLS with its configured cert.
    pub fn encode_listen_tls(addr: &str) -> Vec<u8> {
        encode_listen_inner(addr, true)
    }
    fn encode_listen_inner(addr: &str, tls: bool) -> Vec<u8> {
        let mut o = Vec::new();
        o.push(EFFECT_LISTEN);
        o.push(tls as u8);
        write_str(&mut o, addr);
        o
    }
    pub fn encode_accept(listener_id: u64) -> Vec<u8> {
        let mut o = Vec::new();
        o.push(EFFECT_ACCEPT);
        write_u64(&mut o, listener_id);
        o
    }
    pub fn encode_read(conn_id: u64, max: u32) -> Vec<u8> {
        let mut o = Vec::new();
        o.push(EFFECT_READ);
        write_u64(&mut o, conn_id);
        write_u32(&mut o, max);
        o
    }
    pub fn encode_write(conn_id: u64, data: &[u8]) -> Vec<u8> {
        let mut o = Vec::with_capacity(9 + data.len());
        o.push(EFFECT_WRITE);
        write_u64(&mut o, conn_id);
        o.extend_from_slice(data);
        o
    }
    pub fn encode_close(conn_id: u64) -> Vec<u8> {
        let mut o = Vec::new();
        o.push(EFFECT_CLOSE);
        write_u64(&mut o, conn_id);
        o
    }

    // ── Request decoders (host reactor side; `rest` = body after tag) ─

    /// `(tls, addr)`.
    pub fn decode_listen(rest: &[u8]) -> Option<(bool, String)> {
        let mut c = Cursor::new(rest);
        let tls = c.u8()? != 0;
        Some((tls, c.str()?))
    }
    pub fn decode_accept(rest: &[u8]) -> Option<u64> {
        Cursor::new(rest).u64()
    }
    /// `(conn_id, max)`.
    pub fn decode_read(rest: &[u8]) -> Option<(u64, u32)> {
        let mut c = Cursor::new(rest);
        Some((c.u64()?, c.u32()?))
    }
    /// `(conn_id, data)`. `data` is the remainder after the id.
    pub fn decode_write(rest: &[u8]) -> Option<(u64, Vec<u8>)> {
        let mut c = Cursor::new(rest);
        let cid = c.u64()?;
        Some((cid, c.rest().to_vec()))
    }
    pub fn decode_close(rest: &[u8]) -> Option<u64> {
        Cursor::new(rest).u64()
    }

    // ── Response encoders (host reactor side) ───────────────────────

    pub fn resp_ok_u64(id: u64) -> Vec<u8> {
        let mut o = Vec::with_capacity(9);
        o.push(RESP_OK);
        write_u64(&mut o, id);
        o
    }
    pub fn resp_ok_u32(n: u32) -> Vec<u8> {
        let mut o = Vec::with_capacity(5);
        o.push(RESP_OK);
        write_u32(&mut o, n);
        o
    }
    pub fn resp_ok_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut o = Vec::with_capacity(1 + bytes.len());
        o.push(RESP_OK);
        o.extend_from_slice(bytes);
        o
    }
    pub fn resp_ok_empty() -> Vec<u8> {
        alloc::vec![RESP_OK]
    }
    pub fn resp_err(msg: &str) -> Vec<u8> {
        let mut o = Vec::new();
        o.push(RESP_ERR);
        o.extend_from_slice(msg.as_bytes());
        o
    }

    // ── Response decoders (extension `Context` side) ────────────────

    /// `Some(id)` on `RESP_OK`, `None` on error/short.
    pub fn decode_resp_u64(resp: &[u8]) -> Option<u64> {
        let mut c = Cursor::new(resp);
        match c.u8()? {
            RESP_OK => c.u64(),
            _ => None,
        }
    }
    /// `Some(n)` written on `RESP_OK`, `None` on error/short.
    pub fn decode_resp_u32(resp: &[u8]) -> Option<u32> {
        let mut c = Cursor::new(resp);
        match c.u8()? {
            RESP_OK => c.u32(),
            _ => None,
        }
    }
    /// `Some(bytes)` (possibly empty = EOF) on `RESP_OK`, `None` on error/short.
    pub fn decode_resp_bytes(resp: &[u8]) -> Option<Vec<u8>> {
        let mut c = Cursor::new(resp);
        match c.u8()? {
            RESP_OK => Some(c.rest().to_vec()),
            _ => None,
        }
    }
    /// `true` on `RESP_OK` (for close — body-less ok).
    pub fn decode_resp_ok(resp: &[u8]) -> bool {
        resp.first() == Some(&RESP_OK)
    }
}

// ── HTTP types ──────────────────────────────────────────────────────

/// HTTP method as a single byte tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HttpMethod {
    Get = 0,
    Post = 1,
    Put = 2,
    Delete = 3,
    Patch = 4,
    Head = 5,
    Options = 6,
}

impl HttpMethod {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(HttpMethod::Get),
            1 => Some(HttpMethod::Post),
            2 => Some(HttpMethod::Put),
            3 => Some(HttpMethod::Delete),
            4 => Some(HttpMethod::Patch),
            5 => Some(HttpMethod::Head),
            6 => Some(HttpMethod::Options),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
        }
    }
}

/// An HTTP request the handler wants the host to perform.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl FetchRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn post(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// Encode without the EFFECT_FETCH tag. Use `to_effect_bytes` for
    /// the host-bound representation.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.method as u8);
        write_str(&mut out, &self.url);
        write_u16(&mut out, self.headers.len() as u16);
        for (n, v) in &self.headers {
            write_str(&mut out, n);
            write_str(&mut out, v);
        }
        write_u32(&mut out, self.body.len() as u32);
        out.extend_from_slice(&self.body);
        out
    }

    /// Encode with the EFFECT_FETCH tag prefix.
    pub fn to_effect_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 64);
        out.push(EFFECT_FETCH);
        out.extend_from_slice(&self.encode());
        out
    }

    /// Decode the body of an EFFECT_FETCH (without the tag byte).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(bytes);
        let method = HttpMethod::from_u8(c.u8()?)?;
        let url = c.str()?;
        let header_count = c.u16()? as usize;
        let mut headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            headers.push((c.str()?, c.str()?));
        }
        let body_len = c.u32()? as usize;
        let body = c.take(body_len)?.to_vec();
        Some(FetchRequest {
            method,
            url,
            headers,
            body,
        })
    }
}

/// The host's response to a `FetchRequest`.
#[derive(Debug, Clone, Default)]
pub struct FetchResponse {
    /// HTTP status code. 0 = network/host error.
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl FetchResponse {
    pub fn ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Try to decode the body as UTF-8.
    pub fn text(&self) -> Option<&str> {
        core::str::from_utf8(&self.body).ok()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u16(&mut out, self.status);
        write_u16(&mut out, self.headers.len() as u16);
        for (n, v) in &self.headers {
            write_str(&mut out, n);
            write_str(&mut out, v);
        }
        write_u32(&mut out, self.body.len() as u32);
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut c = Cursor::new(bytes);
        let status = c.u16()?;
        let header_count = c.u16()? as usize;
        let mut headers = Vec::with_capacity(header_count);
        for _ in 0..header_count {
            headers.push((c.str()?, c.str()?));
        }
        let body_len = c.u32()? as usize;
        let body = c.take(body_len)?.to_vec();
        Some(FetchResponse {
            status,
            headers,
            body,
        })
    }

    /// Error response with status 0 and an error message in the body.
    pub fn host_error(msg: impl Into<String>) -> Self {
        Self {
            status: 0,
            headers: Vec::new(),
            body: msg.into().into_bytes(),
        }
    }
}

// ── Codec helpers ───────────────────────────────────────────────────

fn write_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn write_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn write_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn write_str(out: &mut Vec<u8>, s: &str) {
    write_u32(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
    fn str(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        core::str::from_utf8(bytes).ok().map(String::from)
    }
    /// The unconsumed remainder.
    fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_request_roundtrip() {
        let req = FetchRequest::post("https://example.com/api")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer xyz")
            .body(b"{\"key\":\"value\"}".to_vec());
        let bytes = req.encode();
        let decoded = FetchRequest::decode(&bytes).unwrap();
        assert_eq!(decoded.method, HttpMethod::Post);
        assert_eq!(decoded.url, "https://example.com/api");
        assert_eq!(decoded.headers.len(), 2);
        assert_eq!(
            decoded.headers[0],
            (
                String::from("Content-Type"),
                String::from("application/json")
            )
        );
        assert_eq!(decoded.body, b"{\"key\":\"value\"}");
    }

    #[test]
    fn fetch_response_roundtrip() {
        let resp = FetchResponse {
            status: 200,
            headers: alloc::vec![(String::from("X-Foo"), String::from("bar"))],
            body: b"hello world".to_vec(),
        };
        let bytes = resp.encode();
        let decoded = FetchResponse::decode(&bytes).unwrap();
        assert_eq!(decoded.status, 200);
        assert_eq!(decoded.body, b"hello world");
        assert_eq!(decoded.text(), Some("hello world"));
        assert!(decoded.ok());
    }

    #[test]
    fn effect_tag_prefix() {
        let req = FetchRequest::get("https://x.com");
        let bytes = req.to_effect_bytes();
        assert_eq!(bytes[0], EFFECT_FETCH);
        let decoded = FetchRequest::decode(&bytes[1..]).unwrap();
        assert_eq!(decoded.url, "https://x.com");
    }

    #[test]
    fn bytestream_request_roundtrips() {
        use super::bytestream as bs;

        let listen = bs::encode_listen("127.0.0.1:7000");
        assert_eq!(listen[0], EFFECT_LISTEN);
        assert_eq!(
            bs::decode_listen(&listen[1..]),
            Some((false, "127.0.0.1:7000".to_string()))
        );
        let listen_tls = bs::encode_listen_tls("127.0.0.1:7443");
        assert_eq!(listen_tls[0], EFFECT_LISTEN);
        assert_eq!(
            bs::decode_listen(&listen_tls[1..]),
            Some((true, "127.0.0.1:7443".to_string()))
        );

        let accept = bs::encode_accept(42);
        assert_eq!(accept[0], EFFECT_ACCEPT);
        assert_eq!(bs::decode_accept(&accept[1..]), Some(42));

        let read = bs::encode_read(7, 1024);
        assert_eq!(read[0], EFFECT_READ);
        assert_eq!(bs::decode_read(&read[1..]), Some((7, 1024)));

        let write = bs::encode_write(7, b"hello");
        assert_eq!(write[0], EFFECT_WRITE);
        assert_eq!(bs::decode_write(&write[1..]), Some((7, b"hello".to_vec())));

        let close = bs::encode_close(9);
        assert_eq!(close[0], EFFECT_CLOSE);
        assert_eq!(bs::decode_close(&close[1..]), Some(9));
    }

    #[test]
    fn bytestream_response_roundtrips() {
        use super::bytestream as bs;

        assert_eq!(bs::decode_resp_u64(&bs::resp_ok_u64(123)), Some(123));
        assert_eq!(bs::decode_resp_u32(&bs::resp_ok_u32(5)), Some(5));
        assert_eq!(
            bs::decode_resp_bytes(&bs::resp_ok_bytes(b"data")),
            Some(b"data".to_vec())
        );
        // Empty ok-bytes = EOF.
        assert_eq!(
            bs::decode_resp_bytes(&bs::resp_ok_bytes(b"")),
            Some(Vec::new())
        );
        assert!(bs::decode_resp_ok(&bs::resp_ok_empty()));

        // Errors decode to None / false.
        let err = bs::resp_err("boom");
        assert_eq!(bs::decode_resp_u64(&err), None);
        assert_eq!(bs::decode_resp_bytes(&err), None);
        assert!(!bs::decode_resp_ok(&err));
    }
}
