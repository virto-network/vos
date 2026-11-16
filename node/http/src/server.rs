//! A small HTTP/1.1 server on tokio: requests with `Content-Length` bodies
//! over keep-alive connections, plain or in TLS.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

use crate::request::{Large, MAX_HEAD, Request, Response, Slot, content_length};

/// What one connection may take.
#[derive(Clone)]
pub struct Limits {
    /// The most a body may hold, checked against its `Content-Length`
    /// before it is read.
    pub body: usize,
    /// The most an install's body (a `POST` to a path ending in
    /// `/install`) may hold, in place of `body`.
    pub install: usize,
    /// The most a credentialed call's body (a `POST` to a path ending in
    /// `/credentialed`) may hold, in place of `body`.
    pub credentialed: usize,
    /// How long a connection may wait for its next bytes.
    pub idle: Duration,
    /// The most connections at once; more are closed on accept.
    pub connections: usize,
    /// The most install bodies past `body` held at once, from every
    /// connection: past them, a request is answered 503 from its head,
    /// its body unread.
    pub large: usize,
    /// The same for credentialed calls' bodies past `body`, apart from the
    /// installs': a proof of any size takes no install's place.
    pub credentialed_large: usize,
}

/// Bodies past `body` held at once, unless a server says otherwise.
pub const LARGE: usize = 4;
/// Credentialed calls' bodies past `body` held at once, unless a server
/// says otherwise: about 100 MiB of them at their largest.
pub const CREDENTIALED_LARGE: usize = 64;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub type Handler = Arc<dyn Fn(Request) -> BoxFuture<Response> + Send + Sync>;

/// A request's answer from its head, before its body is read (`body` is
/// empty, `peer` set), or `None` to read the body and run the handler:
/// a refusal whose answer never depends on the body.
pub type Head = Arc<dyn Fn(&Request) -> Option<Response> + Send + Sync>;

/// What a connection from an address holds while it lasts, or `None` to
/// close it on accept: a limit per address.
pub type Admit = Arc<dyn Fn(SocketAddr) -> Option<Box<dyn Send>> + Send + Sync>;

/// How long a client has to finish its TLS handshake.
const HANDSHAKE: Duration = Duration::from_secs(10);

/// What a server runs with besides its listener.
#[derive(Clone)]
pub struct Serve {
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub handler: Handler,
    pub limits: Limits,
    pub admit: Option<Admit>,
    pub head: Option<Head>,
}

/// Accept connections on `listener` and answer each request with the
/// handler, each connection a task on the runtime, until the listener
/// fails or `stop` resolves; then end every connection before returning.
/// With TLS, each connection is in TLS.
pub async fn serve(listener: TcpListener, serve: Serve, stop: impl Future<Output = ()>) {
    let mut connections = Vec::new();
    tokio::select! {
        () = accept(listener, serve, &mut connections) => {}
        () = stop => {}
    }
    for connection in connections {
        connection.abort();
        let _ = connection.await;
    }
}

async fn accept(
    listener: TcpListener,
    serve: Serve,
    connections: &mut Vec<tokio::task::JoinHandle<()>>,
) {
    let open = Arc::new(AtomicUsize::new(0));
    let large = Arc::new(AtomicUsize::new(0));
    let credentialed = Arc::new(AtomicUsize::new(0));
    let acceptor = serve.tls.clone().map(tokio_rustls::TlsAcceptor::from);
    while let Ok((stream, peer)) = listener.accept().await {
        // An answer goes as soon as it is written, not once the client
        // acknowledges what went before it.
        let _ = stream.set_nodelay(true);
        connections.retain(|connection| !connection.is_finished());
        let Some(slot) = Slot::take(&open, serve.limits.connections) else {
            continue;
        };
        let admitted = match &serve.admit {
            Some(admit) => match admit(peer) {
                Some(held) => Some(held),
                None => continue,
            },
            None => None,
        };
        let shared = Shared {
            handler: Arc::clone(&serve.handler),
            head: serve.head.clone(),
            limits: serve.limits.clone(),
            large: Arc::clone(&large),
            credentialed: Arc::clone(&credentialed),
        };
        let acceptor = acceptor.clone();
        connections.push(tokio::spawn(async move {
            let _slot = slot;
            let _admitted = admitted;
            let served = match acceptor {
                Some(acceptor) => match timeout(HANDSHAKE, acceptor.accept(stream)).await {
                    Ok(Ok(stream)) => connection(stream, peer, &shared).await,
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "a slow TLS handshake",
                    )),
                },
                None => connection(stream, peer, &shared).await,
            };
            if let Err(error) = served {
                tracing::debug!("an HTTP connection ended: {error}");
            }
        }));
    }
}

/// What every connection of a server shares.
struct Shared {
    handler: Handler,
    head: Option<Head>,
    limits: Limits,
    /// The large bodies held now: installs', and credentialed calls'.
    large: Arc<AtomicUsize>,
    credentialed: Arc<AtomicUsize>,
}

/// How long one request may take to arrive, head and body, from its first
/// byte: a client that trickles bytes cannot hold a connection.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(60);

async fn connection(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    peer: SocketAddr,
    shared: &Shared,
) -> std::io::Result<()> {
    let mut buffer = Vec::with_capacity(4096);
    loop {
        let (response, next) = match read_request(&mut stream, &mut buffer, peer, shared).await? {
            Read::Request(request, used) => {
                let close = closes(&request);
                // The request's bytes leave the buffer before the handler
                // runs: a large body is held once, by the request, and its
                // place is held until the handler drops it or answers.
                buffer.drain(..used);
                buffer.shrink_to(4096);
                let response = (shared.handler)(request).await;
                (response, (!close).then_some(0))
            }
            Read::Answered(response, next) => (response, next),
            Read::Closed => return Ok(()),
        };
        // With no next request to read, say why before closing: the rest
        // of this one may be unread.
        write_response(&mut stream, &response, next.is_none()).await?;
        match next {
            Some(used) => drop(buffer.drain(..used)),
            None => return Ok(()),
        }
    }
}

/// Whether the client asks the connection to close after this request.
fn closes(request: &Request) -> bool {
    request
        .header("connection")
        .is_some_and(|value| value.eq_ignore_ascii_case(b"close"))
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
    timeout(wait, stream.read(chunk)).await.unwrap_or_else(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "an idle or slow connection",
        ))
    })
}

enum Read {
    /// A request, and the bytes of the buffer it used.
    Request(Request, usize),
    /// A request answered without the handler: the answer, and the bytes
    /// of the buffer it used if the connection goes on, `None` to close.
    Answered(Response, Option<usize>),
    /// The client closed between requests.
    Closed,
}

/// A refusal with no body, after which the connection closes.
fn refuse(status: u16) -> Read {
    Read::Answered(Response::new(status, Vec::new()), None)
}

/// Read into `buffer` until it holds `end` bytes.
async fn fill(
    stream: &mut (impl AsyncRead + Unpin),
    buffer: &mut Vec<u8>,
    end: usize,
    idle: Duration,
    deadline: Option<Instant>,
) -> std::io::Result<()> {
    let mut chunk = [0u8; 8192];
    while buffer.len() < end {
        let read = read(stream, &mut chunk, idle, deadline).await?;
        if read == 0 {
            return Err(invalid("the body ended early"));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    Ok(())
}

/// The next request on the connection, or its answer from its head.
async fn read_request(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    buffer: &mut Vec<u8>,
    peer: SocketAddr,
    shared: &Shared,
) -> std::io::Result<Read> {
    let limits = &shared.limits;
    let mut chunk = [0u8; 8192];
    let mut deadline = (!buffer.is_empty()).then(|| Instant::now() + REQUEST_DEADLINE);
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut parsed = httparse::Request::new(&mut headers);
        match parsed.parse(buffer) {
            // A head past the limit is refused, the read that completes it
            // too.
            Ok(httparse::Status::Complete(head)) if head > MAX_HEAD => return Ok(refuse(431)),
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
                    peer: Some(peer),
                    large: None,
                };
                // Bodies come with a length: chunked ones are not read.
                if request.header("transfer-encoding").is_some() {
                    return Ok(refuse(411));
                }
                let length = match request.header("content-length").map(content_length) {
                    Some(Some(length)) => length,
                    Some(None) => return Ok(refuse(400)),
                    None => 0,
                };
                let post = |end: &str| request.method == "POST" && request.path.ends_with(end);
                let (limit, pool) = if post("/install") {
                    (limits.install, Some((&shared.large, limits.large)))
                } else if post("/credentialed") {
                    let pool = (&shared.credentialed, limits.credentialed_large);
                    (limits.credentialed, Some(pool))
                } else {
                    (limits.body, None)
                };
                let large = length > limits.body;
                if length > limit {
                    return Ok(refuse(413));
                }
                let end = head + length;
                let pending = buffer.len() < end;
                let continues = request
                    .header("expect")
                    .is_some_and(|value| value.eq_ignore_ascii_case(b"100-continue"));
                if let Some(answer) = shared.head.as_ref().and_then(|head| head(&request)) {
                    // A large body, or one the client waits to be asked
                    // for, is never read: the connection closes instead.
                    if pending && (large || continues) {
                        return Ok(Read::Answered(answer, None));
                    }
                    fill(stream, buffer, end, limits.idle, deadline).await?;
                    let next = (!closes(&request)).then_some(end);
                    return Ok(Read::Answered(answer, next));
                }
                request.large = match pool.filter(|_| large) {
                    Some((held, most)) => match Slot::take(held, most) {
                        Some(place) => Some(Large { _place: place }),
                        None => return Ok(refuse(503)),
                    },
                    None => None,
                };
                if pending && continues {
                    stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
                    stream.flush().await?;
                }
                fill(stream, buffer, end, limits.idle, deadline).await?;
                request.body = buffer[head..end].to_vec();
                return Ok(Read::Request(request, end));
            }
            Ok(httparse::Status::Partial) => {
                if buffer.len() > MAX_HEAD {
                    return Ok(refuse(431));
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
            // More header lines than it parses: a head too large, as one
            // past its bytes.
            Err(httparse::Error::TooManyHeaders) => return Ok(refuse(431)),
            Err(_) => return Ok(refuse(400)),
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        413 => "Content Too Large",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The status `bytes`, a client's whole sending, is answered from its
    /// head, if it is.
    fn answered(bytes: Vec<u8>) -> Option<u16> {
        let shared = Shared {
            handler: Arc::new(|_| Box::pin(async { Response::not_found() })),
            head: None,
            limits: Limits {
                body: 1 << 10,
                install: 1 << 10,
                credentialed: 1 << 10,
                idle: Duration::from_secs(5),
                connections: 1,
                large: LARGE,
                credentialed_large: CREDENTIALED_LARGE,
            },
            large: Arc::new(AtomicUsize::new(0)),
            credentialed: Arc::new(AtomicUsize::new(0)),
        };
        let mut stream = std::io::Cursor::new(bytes);
        let peer = SocketAddr::from(([127, 0, 0, 1], 1));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("a runtime");
        let read = runtime.block_on(read_request(&mut stream, &mut Vec::new(), peer, &shared));
        match read.expect("a read") {
            Read::Answered(response, None) => Some(response.status),
            _ => None,
        }
    }

    fn head(lines: &[String], end: bool) -> Vec<u8> {
        let mut head = String::from("GET / HTTP/1.1\r\n");
        for line in lines {
            head.push_str(line);
            head.push_str("\r\n");
        }
        if end {
            head.push_str("\r\n");
        }
        head.into_bytes()
    }

    #[test]
    fn a_head_completed_past_the_limit_is_431() {
        let long = format!("x: {}", "a".repeat(MAX_HEAD));
        assert_eq!(answered(head(&[long], true)), Some(431));
    }

    #[test]
    fn a_head_still_partial_past_the_limit_is_431() {
        let long = format!("x: {}", "a".repeat(MAX_HEAD + 8192));
        assert_eq!(answered(head(&[long], false)), Some(431));
    }

    #[test]
    fn more_header_lines_than_are_parsed_is_431() {
        let lines: Vec<String> = (0..40).map(|i| format!("x{i}: 1")).collect();
        assert_eq!(answered(head(&lines, true)), Some(431));
        let few: Vec<String> = (0..4).map(|i| format!("x{i}: 1")).collect();
        assert_eq!(answered(head(&few, true)), None, "a request read");
    }
}
