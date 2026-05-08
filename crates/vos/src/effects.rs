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
/// Result: rkyv-encoded `Value` (the reply).
pub const EFFECT_ASK: u8 = 0x01;

/// HTTP request. Synchronous from the handler's perspective; the
/// host performs the request asynchronously and returns the response.
/// Payload: see `FetchRequest::encode`.
/// Result: see `FetchResponse::encode`.
pub const EFFECT_FETCH: u8 = 0x02;

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
    fn str(&mut self) -> Option<String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        core::str::from_utf8(bytes).ok().map(String::from)
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
}
