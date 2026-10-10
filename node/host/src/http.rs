//! A small HTTP/1.1 server for the node's ingress: requests with
//! `Content-Length` bodies over keep-alive connections, plain or in TLS.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use smol::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use smol::net::TcpListener;

/// The most a request's head may hold.
const MAX_HEAD: usize = 16 << 10;

/// The most a body may hold, by method and path.
pub type BodyLimit = Arc<dyn Fn(&str, &str) -> usize + Send + Sync>;

/// What one connection may take.
#[derive(Clone)]
pub struct Limits {
    /// Checked against a body's `Content-Length` before it is read.
    pub body: BodyLimit,
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
        connections.retain(|connection| !connection.is_finished());
        if open.fetch_add(1, Ordering::SeqCst) >= limits.connections {
            open.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let handler = Arc::clone(&handler);
        let limits = limits.clone();
        let open = Arc::clone(&open);
        let acceptor = acceptor.clone();
        connections.push(spawn(Box::pin(async move {
            let served = match acceptor {
                Some(acceptor) => {
                    let handshake = async { Some(acceptor.accept(stream).await) };
                    let late = async {
                        smol::Timer::after(HANDSHAKE).await;
                        None
                    };
                    match smol::future::or(handshake, late).await {
                        Some(Ok(stream)) => connection(stream, handler, &limits).await,
                        Some(Err(error)) => Err(error),
                        None => Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "a slow TLS handshake",
                        )),
                    }
                }
                None => connection(stream, handler, &limits).await,
            };
            if let Err(error) = served {
                tracing::debug!("an ingress connection ended: {error}");
            }
            open.fetch_sub(1, Ordering::SeqCst);
        })));
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
    smol::future::or(stream.read(chunk), async {
        smol::Timer::after(wait).await;
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "an idle or slow connection",
        ))
    })
    .await
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
                let method = parsed.method.unwrap_or_default().to_string();
                let path = parsed.path.unwrap_or_default().to_string();
                let headers: Vec<(String, Vec<u8>)> = parsed
                    .headers
                    .iter()
                    .map(|header| (header.name.to_string(), header.value.to_vec()))
                    .collect();
                let header = |name: &str| {
                    headers
                        .iter()
                        .find(|(header, _)| header.eq_ignore_ascii_case(name))
                        .map(|(_, value)| value.as_slice())
                };
                // Bodies come with a length: chunked ones are not read.
                if header("transfer-encoding").is_some() {
                    return Ok(Read::Refuse(411));
                }
                let length = match header("content-length") {
                    Some(value) => match std::str::from_utf8(value)
                        .ok()
                        .and_then(|value| value.trim().parse::<usize>().ok())
                    {
                        Some(length) => length,
                        None => return Ok(Read::Refuse(400)),
                    },
                    None => 0,
                };
                if length > (limits.body)(&method, &path) {
                    return Ok(Read::Refuse(413));
                }
                let pending = buffer.len() < head + length;
                if pending
                    && header("expect")
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
                let body = buffer[head..head + length].to_vec();
                let request = Request {
                    method,
                    path,
                    headers,
                    body,
                };
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
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
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
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await?;
    stream.flush().await
}
