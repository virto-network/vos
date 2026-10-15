//! A small HTTP/1.1 server for the node's ingress: requests with
//! `Content-Length` bodies over keep-alive connections, plain or in TLS.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use smol::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use smol::net::TcpListener;

use crate::timeout;

/// The most a request's or an answer's head may hold.
pub(crate) const MAX_HEAD: usize = 16 << 10;

/// What one connection may take.
#[derive(Clone)]
pub struct Limits {
    /// The most a body may hold, checked against its `Content-Length`
    /// before it is read.
    pub body: usize,
    /// The most an install's body (a `POST` to a path ending in
    /// `/install`) may hold, in place of `body`.
    pub install: usize,
    /// How long a connection may wait for its next bytes.
    pub idle: Duration,
    /// The most connections at once; more are closed on accept.
    pub connections: usize,
}

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_slice())
    }
}

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

pub type Handler =
    Arc<dyn Fn(Request) -> Pin<Box<dyn Future<Output = Response> + Send>> + Send + Sync>;

/// How long a client has to finish its TLS handshake.
const HANDSHAKE: Duration = Duration::from_secs(10);

/// Accept connections on `listener` and answer each request with
/// `handler`, until the listener fails or `stop` resolves; then end every
/// connection before returning. With `tls`, each connection is in TLS.
pub async fn serve(
    listener: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    handler: Handler,
    limits: Limits,
    spawn: impl Fn(Pin<Box<dyn Future<Output = ()> + Send>>) -> smol::Task<()>,
    stop: impl Future<Output = ()>,
) {
    let mut connections: Vec<smol::Task<()>> = Vec::new();
    let accepting = async {
        accept(listener, tls, handler, limits, &spawn, &mut connections).await;
    };
    smol::future::or(accepting, stop).await;
    for connection in connections {
        connection.cancel().await;
    }
}

async fn accept(
    listener: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    handler: Handler,
    limits: Limits,
    spawn: &impl Fn(Pin<Box<dyn Future<Output = ()> + Send>>) -> smol::Task<()>,
    connections: &mut Vec<smol::Task<()>>,
) {
    let open = Arc::new(AtomicUsize::new(0));
    let acceptor = tls.map(futures_rustls::TlsAcceptor::from);
    while let Ok((stream, _)) = listener.accept().await {
        // An answer goes as soon as it is written, not once the client
        // acknowledges what went before it.
        let _ = stream.set_nodelay(true);
        connections.retain(|connection| !connection.is_finished());
        let Some(slot) = Slot::take(&open, limits.connections) else {
            continue;
        };
        let handler = Arc::clone(&handler);
        let limits = limits.clone();
        let acceptor = acceptor.clone();
        connections.push(spawn(Box::pin(async move {
            let _slot = slot;
            let served = match acceptor {
                Some(acceptor) => match timeout(HANDSHAKE, acceptor.accept(stream)).await {
                    Some(Ok(stream)) => connection(stream, handler, &limits).await,
                    Some(Err(error)) => Err(error),
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "a slow TLS handshake",
                    )),
                },
                None => connection(stream, handler, &limits).await,
            };
            if let Err(error) = served {
                tracing::debug!("an ingress connection ended: {error}");
            }
        })));
    }
}

/// A connection's place among the open ones, given back when its task
/// ends, however it ends: a handler's panic, or a cancel, too.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    /// A place among `open`, if fewer than `most` hold one.
    fn take(open: &Arc<AtomicUsize>, most: usize) -> Option<Self> {
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

/// How long one request may take to arrive, head and body, from its first
/// byte: a client that trickles bytes cannot hold a connection.
const REQUEST_DEADLINE: Duration = Duration::from_secs(60);

async fn connection(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    handler: Handler,
    limits: &Limits,
) -> std::io::Result<()> {
    let mut buffer = Vec::with_capacity(4096);
    loop {
        let (request, used) = match read_request(&mut stream, &mut buffer, limits).await? {
            Read::Request(request, used) => (request, used),
            Read::Closed => return Ok(()),
            Read::Refuse(status) => {
                // Say why before closing: the rest of the request is unread.
                let response = Response::new(status, Vec::new());
                return write_response(&mut stream, &response, true).await;
            }
        };
        buffer.drain(..used);
        let close = request
            .header("connection")
            .is_some_and(|value| value.eq_ignore_ascii_case(b"close"));
        let response = handler(request).await;
        write_response(&mut stream, &response, close).await?;
        if close {
            return Ok(());
        }
    }
}

/// A `Content-Length` header's value, if it is a length.
pub(crate) fn content_length(value: &[u8]) -> Option<usize> {
    std::str::from_utf8(value).ok()?.trim().parse().ok()
}

fn invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string())
}

/// Read what the client sends next, or fail once it has been idle too long
/// or its request is past its deadline.
async fn read(
    stream: &mut (impl AsyncRead + Unpin),
    chunk: &mut [u8],
    idle: Duration,
    deadline: Option<Instant>,
) -> std::io::Result<usize> {
    let wait = match deadline {
        Some(deadline) => idle.min(deadline.saturating_duration_since(Instant::now())),
        None => idle,
    };
    timeout(wait, stream.read(chunk)).await.unwrap_or_else(|| {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "an idle or slow connection",
        ))
    })
}

enum Read {
    Request(Request, usize),
    /// The client closed between requests.
    Closed,
    /// A request the server will not read: answer this status and close.
    Refuse(u16),
}

/// The next request on the connection, and the bytes of `buffer` it used.
async fn read_request(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    buffer: &mut Vec<u8>,
    limits: &Limits,
) -> std::io::Result<Read> {
    let mut chunk = [0u8; 8192];
    let mut deadline = (!buffer.is_empty()).then(|| Instant::now() + REQUEST_DEADLINE);
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut parsed = httparse::Request::new(&mut headers);
        match parsed.parse(buffer) {
            Ok(httparse::Status::Complete(head)) => {
                let mut request = Request {
                    method: parsed.method.unwrap_or_default().to_string(),
                    path: parsed.path.unwrap_or_default().to_string(),
                    headers: parsed
                        .headers
                        .iter()
                        .map(|header| (header.name.to_string(), header.value.to_vec()))
                        .collect(),
                    body: Vec::new(),
                };
                // Bodies come with a length: chunked ones are not read.
                if request.header("transfer-encoding").is_some() {
                    return Ok(Read::Refuse(411));
                }
                let length = match request.header("content-length").map(content_length) {
                    Some(Some(length)) => length,
                    Some(None) => return Ok(Read::Refuse(400)),
                    None => 0,
                };
                let limit = if request.method == "POST" && request.path.ends_with("/install") {
                    limits.install
                } else {
                    limits.body
                };
                if length > limit {
                    return Ok(Read::Refuse(413));
                }
                let pending = buffer.len() < head + length;
                if pending
                    && request
                        .header("expect")
                        .is_some_and(|value| value.eq_ignore_ascii_case(b"100-continue"))
                {
                    stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
                    stream.flush().await?;
                }
                while buffer.len() < head + length {
                    let read = read(stream, &mut chunk, limits.idle, deadline).await?;
                    if read == 0 {
                        return Err(invalid("the body ended early"));
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                }
                request.body = buffer[head..head + length].to_vec();
                return Ok(Read::Request(request, head + length));
            }
            Ok(httparse::Status::Partial) => {
                if buffer.len() > MAX_HEAD {
                    return Ok(Read::Refuse(431));
                }
                let read = read(stream, &mut chunk, limits.idle, deadline).await?;
                if read == 0 {
                    return if buffer.is_empty() {
                        Ok(Read::Closed)
                    } else {
                        Err(invalid("the head ended early"))
                    };
                }
                deadline.get_or_insert_with(|| Instant::now() + REQUEST_DEADLINE);
                buffer.extend_from_slice(&chunk[..read]);
            }
            Err(_) => return Ok(Read::Refuse(400)),
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        413 => "Content Too Large",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

async fn write_response(
    stream: &mut (impl AsyncWrite + Unpin),
    response: &Response,
    close: bool,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n{}\r\n",
        response.status,
        reason(response.status),
        response.body.len(),
        if close { "Connection: close\r\n" } else { "" },
    );
    // One write: the head and its body leave together.
    let mut answer = Vec::with_capacity(head.len() + response.body.len());
    answer.extend_from_slice(head.as_bytes());
    answer.extend_from_slice(&response.body);
    stream.write_all(&answer).await?;
    stream.flush().await
}
